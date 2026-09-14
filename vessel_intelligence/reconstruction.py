"""Evidence-scoped content recovery. Stored objects never execute as dashboard HTML."""
import argparse,collections,email,email.policy,hashlib,json,pathlib,re,sqlite3,struct,subprocess,time,xml.etree.ElementTree as ET
from core import dbopen,executable,ns,putmeta,dumps,endpoints
VERSION='1.0'
MAX_OBJECT=32*1024*1024
MAX_TOTAL=1024*1024*1024
SCHEMA="""
CREATE TABLE IF NOT EXISTS artifacts(id INTEGER PRIMARY KEY,kind TEXT,frame INTEGER,t INTEGER,stream TEXT,src TEXT,dst TEXT,sport TEXT,dport TEXT,name TEXT,mime TEXT,size INTEGER,status TEXT,confidence TEXT,reason TEXT,frames TEXT,detail TEXT,preview TEXT,path TEXT,sha256 TEXT);
CREATE TABLE IF NOT EXISTS artifact_links(artifact_id INTEGER,vessel_id INTEGER,session_id INTEGER,reason TEXT,PRIMARY KEY(artifact_id,vessel_id,session_id));
CREATE INDEX IF NOT EXISTS artifact_kind ON artifacts(kind,frame);
"""

def values(p,name):return [f.get('show','') for f in p.iter('field') if f.get('name')==name]
def val(p,name,default=''):return next(iter(values(p,name)),default)
def unhex(f):
 s=f.get('value','')
 if len(s)>MAX_OBJECT*2 or len(s)%2:return None
 try:return bytes.fromhex(s)
 except ValueError:return None

def payload_for(p,proto):
 """Only slice a byte field covering the exact protocol offsets in the same buffer."""
 start=int(proto.get('pos','0'));size=int(proto.get('size','0'))
 if size>MAX_OBJECT:return None
 if proto.get('name')=='imf' and values(p,'smtp.data.reassembled.length'):
  expected=int(val(p,'smtp.data.reassembled.length','0'))
  if expected>MAX_OBJECT:return None
  fragments=sorted((int(f.get('pos','0')),unhex(f)) for f in p.iter('field') if f.get('name')=='smtp.data.fragment')
  buf=bytearray()
  for pos,data in fragments:
   if data is None or pos>len(buf):return None
   overlap=min(len(data),len(buf)-pos)
   if buf[pos:pos+overlap]!=data[:overlap]:return None
   buf.extend(data[overlap:])
   if len(buf)>expected:return None
  if len(buf)==expected and start+size<=expected:return bytes(buf[start:start+size])
  return None
 for name in ('tcp.reassembled.data','tcp.payload','udp.payload'):
  for f in p.iter('field'):
   if f.get('name')!=name:continue
   pos=int(f.get('pos','0'));data=unhex(f)
   if data is not None and pos<=start and start+size<=pos+len(data):return data[start-pos:start-pos+size]
 return None

def media_type(data,claimed):
 mime=claimed.split(';')[0].strip().lower()
 if data.startswith(b'\x89PNG\r\n\x1a\n'):return 'Image','image/png'
 if data.startswith(b'\xff\xd8\xff'):return 'Image','image/jpeg'
 if data[:6] in (b'GIF87a',b'GIF89a'):return 'Image','image/gif'
 if data.startswith(b'RIFF') and data[8:12]==b'WEBP':return 'Image','image/webp'
 if len(data)>12 and data[4:8]==b'ftyp':return 'Video','video/mp4'
 if data.startswith(b'\x1a\x45\xdf\xa3') and b'webm' in data[:128]:return 'Video','video/webm'
 if mime.startswith('image/'):return 'Image',mime
 if mime.startswith('video/'):return 'Video',mime
 return 'HTTP',mime or 'application/octet-stream'

def smpp_message(data):
 """Strict complete submit_sm/deliver_sm PDU validation, including mandatory fields/TLV lengths."""
 if not data or len(data)<16:return None
 length,command,status,seq=struct.unpack('!IIII',data[:16])
 if length!=len(data) or length>1024*1024 or command not in (4,5) or status!=0 or not 0<seq<0x80000000:return None
 pos=16
 def cstr(maxlen):
  nonlocal pos
  end=data.find(b'\0',pos,min(len(data),pos+maxlen))
  if end<0:raise ValueError()
  r=data[pos:end];pos=end+1;return r.decode('ascii')
 def take(n):
  nonlocal pos
  if pos+n>len(data):raise ValueError()
  r=data[pos:pos+n];pos+=n;return r
 try:
  cstr(6);take(2);sender=cstr(21);take(2);recipient=cstr(21)
  esm,protocol,priority=take(3);cstr(17);cstr(17);registered,replace,coding,default,mlen=take(5);message=take(mlen)
  while pos<len(data):
   tag,n=struct.unpack('!HH',take(4));v=take(n)
   if tag==0x424:
    if message:raise ValueError()
    message=v
  if esm&0x40:
   if not message or message[0]+1>len(message):raise ValueError()
   udh=message[:message[0]+1].hex();message=message[message[0]+1:]
  else:udh=''
  if coding==8:text=message.decode('utf-16-be')
  elif coding==3:text=message.decode('latin1')
  elif coding==0:
   alphabet='@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !"#¤%&\'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà'
   ext={10:'\f',20:'^',40:'{',41:'}',47:'\\',60:'[',61:'~',62:']',64:'|',101:'€'};chars=[];escape=False
   for b in message:
    if b>127:raise ValueError()
    if escape:
     if b not in ext:raise ValueError()
     chars.append(ext[b]);escape=False
    elif b==27:escape=True
    else:chars.append(alphabet[b])
   if escape:raise ValueError()
   text=''.join(chars)
  else:text='[Binary/unsupported SMS coding; raw PDU available]'
  return dict(sender=sender,recipient=recipient,text=text,data_coding=coding,sequence=seq,command='submit_sm' if command==4 else 'deliver_sm',udh=udh,multipart='UDH present; segment not claimed as complete message' if udh else 'No UDH')
 except (ValueError,UnicodeError,IndexError,struct.error):return None

class Writer:
 def __init__(self,db,out):self.db=db;self.out=out;self.total=0;self.count=0;out.mkdir(parents=True,exist_ok=True)
 def add(self,p,kind,name,mime,data=None,status='Observed',detail=None,preview='',refs=None):
  self.count+=1
  if self.count>25000:raise RuntimeError('Artifact count limit reached (25000); results are partial')
  frame=int(val(p,'frame.number','0'));refs=sorted(set(refs or [frame]));endpoint_fields={name:values(p,name) for name in ('frame.protocols','ip.src','ip.dst','ipv6.src','ipv6.dst','tcp.srcport','tcp.dstport','udp.srcport','udp.dstport') if values(p,name)};src,sp,dst,dp,*_=endpoints(endpoint_fields);size=len(data) if data is not None else 0
  detail=detail or {};claimed=data is not None
  if size>MAX_OBJECT or self.total+size>MAX_TOTAL:data=None;status='Not stored: configured size limit';claimed=False
  sha=hashlib.sha256(data).hexdigest() if data is not None else '';path=''
  if data is not None:
   path=sha+'.bin';dest=self.out/path
   if not dest.exists():dest.write_bytes(data)
   self.total+=size
  reason='Recoverable content is an exposure candidate, not proof of unauthorized disclosure. '+('Bytes supplied by protocol dissection; see completeness and contributing frames.' if claimed else 'Metadata or fragment only; complete content not recovered.')
  cursor=self.db.execute('INSERT INTO artifacts VALUES(NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(kind,frame,ns(val(p,'frame.time_epoch','0')),val(p,'tcp.stream',val(p,'udp.stream')),src,dst,sp,dp,name[:512],mime,size,status,'Medium' if claimed else 'Low',reason,dumps(refs),dumps(detail),preview[:65536],path,sha))
  aid=cursor.lastrowid
  # All contributing frames must share the very same observed session mapping.
  common=None
  for f in refs:
   links={(r['vessel_id'],r['session_id']) for r in self.db.execute('SELECT vessel_id,session_id FROM links WHERE frame=?',(f,))}
   common=links if common is None else common&links
   if not common:break
  if not detail.get('unverified_reassembly'):
   for vid,sid in common or []:self.db.execute('INSERT INTO artifact_links VALUES(?,?,?,?)',(aid,vid,sid,'Every contributing frame shares this session mapping; terminal candidates remain terminal-level.'))
  return aid

def packet_artifacts(p,w):
 frame=int(val(p,'frame.number','0'));refs=[frame]
 for name in ('tcp.segment','smtp.data.fragment','gsm_sms.fragment'):
  refs += [int(v) for v in values(p,name) if v.isdigit()]
 incomplete=any(values(p,x) for x in ('tcp.segment.overlap.conflict','tcp.segment.error','smtp.data.fragment.error','_ws.malformed'))
 # ICMP quoted application headers are not live HTTP/email messages.
 if p.find("proto[@name='icmp']") is not None or p.find("proto[@name='icmpv6']") is not None:return
 for h in p.findall("proto[@name='http']"):
  detail={f.get('name'):f.get('show','') for f in h.iter('field') if f.get('name') in ('http.host','http.request.full_uri','http.request.uri','http.request.method','http.response.code','http.content_type','http.content_length','http.content_encoding','http.content_range','http.transfer_encoding','http.authorization','http.cookie','http.set_cookie')}
  detail['decoder']='TShark HTTP reassembly';detail['unverified_reassembly']=bool(values(p,'tcp.segment.count') and not values(p,'tcp.segment'))
  bodies=[f for f in h.iter('field') if f.get('name')=='http.file_data']
  if not bodies:
   w.add(p,'HTTP',detail.get('http.request.uri','HTTP headers'),'text/plain',detail=detail,preview=json.dumps(detail,indent=2),refs=refs);continue
  for b in bodies:
   data=unhex(b);data=data if data is not None else b''
   kind,mime=media_type(data,detail.get('http.content_type',''));status='Decoded body; completeness unverified'
   if detail.get('http.content_range') or detail.get('http.response.code')=='206':status='Partial/range object; not a complete file'
   elif detail.get('http.content_length','').isdigit() and int(detail['http.content_length'])==len(data):status='Complete declared HTTP body'
   elif 'chunked' in detail.get('http.transfer_encoding','').lower():status='Reassembled chunked body; end verification required'
   if incomplete:status='Reassembly conflict or malformed content'
   if b.get('size','0').isdigit() and int(b.get('size','0'))>MAX_OBJECT:status='Not stored: object exceeds 32 MiB';data=None
   preview=data[:65536].decode('utf8',errors='replace') if data and (mime.startswith('text/') or mime in ('application/json','application/x-www-form-urlencoded','application/xml')) else ''
   w.add(p,kind,detail.get('http.request.uri') or f'http-frame-{frame}',mime,data,status,detail,preview,refs)
 for imf in p.findall("proto[@name='imf']"):
  data=payload_for(p,imf);detail={x:val(p,x) for x in ('imf.from','imf.to','imf.subject','imf.message_id')};detail['decoder']='TShark IMF, exact offset slice where available'
  preview='';status='Email metadata only; body unavailable'
  if data:
   msg=email.message_from_bytes(data,policy=email.policy.default)
   if not msg.keys():status='Email fragment; headers absent'
   else:status='Recovered message bytes; capture completeness unverified'
   text=[]
   for part in msg.walk():
    if part.is_multipart():continue
    body=part.get_payload(decode=True)
    if not isinstance(body,bytes):continue
    if part.get_content_type()=='text/plain':
     try:text.append(body[:65536].decode(part.get_content_charset() or 'utf8',errors='replace'))
     except LookupError:text.append(body[:65536].decode('utf8',errors='replace'))
    if part.get_filename():
     kind,mime=media_type(body,part.get_content_type());kind=kind if kind in ('Image','Video') else 'Attachment'
     w.add(p,kind,part.get_filename(),mime,body,'Decoded email attachment; parent completeness unverified',{'parent_email_frame':frame,'mime_encoding':part.get('Content-Transfer-Encoding','')},refs=refs)
   preview='\n'.join(text)
  w.add(p,'Email',f'email-frame-{frame}.eml','message/rfc822',data,status,detail,preview,refs)
 sms_seen=False
 for proto in p.findall("proto[@name='smpp']"):
  raw=payload_for(p,proto);sms=smpp_message(raw)
  if sms:sms_seen=True;w.add(p,'SMS',f'sms-frame-{frame}.pdu','application/octet-stream',raw,'Validated SMPP message segment' if sms['udh'] else 'Validated SMPP message',sms,sms['text'],refs)
 # Other native SMS dissectors expose the actual decoded text; no port inference.
 if values(p,'gsm_sms.sms_text'):
  w.add(p,'SMS',f'gsm-sms-frame-{frame}','text/plain',status='Dissector-decoded SMS text; message/segment completeness unverified',detail={'decoder':'gsm_sms','text':values(p,'gsm_sms.sms_text')},preview='\n'.join(values(p,'gsm_sms.sms_text')),refs=refs)
 ports=[val(p,x) for x in ('tcp.srcport','tcp.dstport','udp.srcport','udp.dstport')]
 if set(ports)&{'5002','5003'} and not sms_seen:
  field=next((f for f in p.iter('field') if f.get('name') in ('tcp.payload','udp.payload')),None);raw=unhex(field) if field is not None else None;sms=smpp_message(raw)
  if sms:w.add(p,'SMS',f'sms-frame-{frame}.pdu','application/octet-stream',raw,'Validated SMPP message',sms,sms['text'],refs)
  else:w.add(p,'Ports 5002/5003',f'port-payload-frame-{frame}.bin','application/octet-stream',raw,'Unknown protocol payload' if raw else 'No payload (control/ACK packet)',{'note':'Port number does not identify SMS. No valid complete SMPP message was decoded.','protocols':val(p,'frame.protocols')},raw[:4096].hex(' ') if raw else '',[frame])

def build(dbpath,keylog=None):
 dbpath=pathlib.Path(dbpath).resolve();db=dbopen(dbpath);db.executescript(SCHEMA)
 if db.execute("SELECT value FROM meta WHERE key='reconstruction_version'").fetchone():db.close();return
 source=pathlib.Path(json.loads(db.execute("SELECT value FROM meta WHERE key='pcap'").fetchone()[0]));before=source.stat();h=hashlib.sha256()
 with source.open('rb') as f:
  while b:=f.read(8*1024*1024):h.update(b)
 expected=json.loads(db.execute("SELECT value FROM meta WHERE key='sha256'").fetchone()[0])
 if h.hexdigest()!=expected:db.close();raise ValueError('Source hash changed; content reconstruction refused')
 db.execute('DELETE FROM artifact_links');db.execute('DELETE FROM artifacts');putmeta(db,'reconstruction_status','Processing');db.commit()
 out=dbpath.parent/'reconstructed';w=Writer(db,out);err=(dbpath.parent/'reconstruction-tshark.log').open('w',encoding='utf8');root=None;proc=None
 try:
  cmd=[executable('tshark'),'-n','-l','-r',str(source),'-d','tcp.port==5002,smpp','-d','tcp.port==5003,smpp','-Y','http or imf or smpp or gsm_sms or tcp.port==5002 or tcp.port==5003 or udp.port==5002 or udp.port==5003','-T','pdml']
  if keylog:cmd+=['-o','tls.keylog_file:'+str(pathlib.Path(keylog).resolve())]
  proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=err)
  for ev,p in ET.iterparse(proc.stdout,events=('start','end')):
   if root is None:root=p
   if ev!='end' or p.tag!='packet':continue
   packet_artifacts(p,w)
   if w.count%100==0:putmeta(db,'reconstruction_objects',w.count);db.commit()
   p.clear();root.clear()
  if proc.wait():raise RuntimeError('Reconstruction decoder failed; see reconstruction-tshark.log')
  after=source.stat()
  if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise RuntimeError('Source changed during reconstruction')
  putmeta(db,'reconstruction_status','Complete');putmeta(db,'reconstruction_version',VERSION);putmeta(db,'reconstruction_objects',w.count);db.commit()
 except Exception as exc:
  putmeta(db,'reconstruction_status','Partial/failed: '+str(exc));db.commit();raise
 finally:
  if proc and proc.poll() is None:proc.kill();proc.wait()
  if proc:proc.stdout.close()
  err.close();db.close()

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('database');p.add_argument('--keylog');a=p.parse_args();build(a.database,a.keylog)
