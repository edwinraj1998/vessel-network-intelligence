"""Stream protocol evidence into SQLite for the Satellite Intelligence workspace."""
import argparse,collections,hashlib,json,pathlib,sqlite3,subprocess,time,xml.etree.ElementTree as ET
from core import dbopen,executable,ns,putmeta,dumps
VERSION='3.0'
SCHEMA='''CREATE TABLE IF NOT EXISTS intelligence_events(frame INTEGER,category TEXT,t INTEGER,src TEXT,dst TEXT,sport TEXT,dport TEXT,protocols TEXT,summary TEXT,raw TEXT,PRIMARY KEY(frame,category));
CREATE INDEX IF NOT EXISTS intelligence_category ON intelligence_events(category,t);
CREATE TABLE IF NOT EXISTS intelligence_rtp(frame INTEGER PRIMARY KEY,t INTEGER,stream TEXT,src TEXT,dst TEXT,sport TEXT,dport TEXT,ssrc TEXT,seq INTEGER,rtp_time INTEGER,pt INTEGER,payload BLOB);
CREATE INDEX IF NOT EXISTS intelligence_rtp_stream ON intelligence_rtp(stream,t);
'''
PROTOCOLS={'stun':{'stun','turnchannel'},'ss7':{'mtp2','mtp3','m3ua','sccp','tcap','gsm_map','isup','diameter','gtpv2'},'voip':{'sip','sdp','rtp','rtcp','srtp'},'cctv':{'rtsp','rtp','rtcp'}}

def packet(p):
 d=collections.defaultdict(list)
 for f in p.iter('field'):
  name=f.get('name','')
  if not name or name in ('tcp.payload','tcp.reassembled.data','data.data'):continue
  if len(d)<2000:d[name].append(f.get('show',f.get('value',''))[:4096])
 return dict(d)

def ingest(db,p):
 d=packet(p);first=lambda k,default='':next(iter(d.get(k,[])),default)
 if not first('frame.number') or not first('frame.time_epoch'):return
 frame=int(first('frame.number'));t=ns(first('frame.time_epoch'));src=first('ip.src',first('ipv6.src'));dst=first('ip.dst',first('ipv6.dst'));sp=first('udp.srcport',first('tcp.srcport'));dp=first('udp.dstport',first('tcp.dstport'));protocols=first('frame.protocols');layers=set(protocols.split(':'))
 categories={k for k,v in PROTOCOLS.items() if layers&v}
 sensitive={k:v for k,v in d.items() if any(s in k.lower() for s in ('imsi','msisdn','imei','sms_text','smpp.source_addr','smpp.destination_addr','smpp.message'))}
 if sensitive:categories.add('subscriber')
 if 'rtp' in layers and 'rtsp' not in layers:categories.discard('cctv') # RTP alone is not a camera.
 summary=' | '.join(f'{k}: {",".join(v)[:180]}' for k,v in d.items() if k in ('sip.Call-ID','sip.Method','sip.Status-Code','rtsp.method','rtsp.url','stun.id','rtp.ssrc','gsm_sms.sms_text','gsm_map.imsi','e212.imsi'))[:1000] or protocols
 for category in categories:db.execute('INSERT OR REPLACE INTO intelligence_events VALUES(?,?,?,?,?,?,?,?,?,?)',(frame,category,t,src,dst,sp,dp,protocols,summary,dumps(d)))
 if 'rtp' in layers and not layers&{'srtp','dtls'} and first('rtp.payload'):
  try:
   # G.711 static payload types only. Dynamic/SRTP media stays metadata-only.
   pt=int(first('rtp.p_type','-1'));raw=bytes.fromhex(first('rtp.payload').replace(':',''))
   if pt not in (0,8) or len(raw)>8192:return
   section=first('frame.section_number','1');interface=first('frame.interface_id','0');ssrc=first('rtp.ssrc')
   key=hashlib.sha256(dumps([section,interface,src,sp,dst,dp,ssrc,pt,first('udp.stream')]).encode()).hexdigest()[:24]
   db.execute('INSERT OR REPLACE INTO intelligence_rtp VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(frame,t,key,src,dst,sp,dp,ssrc,int(first('rtp.seq')),int(first('rtp.timestamp')),pt,raw))
  except (ValueError,TypeError):pass

def build(dbpath):
 db=dbopen(dbpath);db.executescript(SCHEMA)
 if db.execute("SELECT 1 FROM meta WHERE key='intelligence_version'").fetchone():db.close();return
 source=pathlib.Path(json.loads(db.execute("SELECT value FROM meta WHERE key='pcap'").fetchone()[0]));before=source.stat();sha=hashlib.sha256()
 with source.open('rb') as f:
  while b:=f.read(8*1024*1024):sha.update(b)
 if sha.hexdigest()!=json.loads(db.execute("SELECT value FROM meta WHERE key='sha256'").fetchone()[0]):db.close();raise ValueError('Source SHA-256 mismatch')
 putmeta(db,'intelligence_status','Processing');db.commit();proc=None
 try:
  available=subprocess.check_output([executable('tshark'),'-G','protocols'],text=True,encoding='utf8',errors='replace');names={line.split('\t')[2] for line in available.splitlines() if len(line.split('\t'))>=3}
  wanted=set.union(*PROTOCOLS.values())|{'gsm_sms','smpp','e212'};selected=sorted(wanted&names)
  if not selected:raise RuntimeError('Required protocol dissectors unavailable')
  log=pathlib.Path(dbpath).parent/'intelligence-tshark.log'
  with log.open('w',encoding='utf8') as err:
   proc=subprocess.Popen([executable('tshark'),'-n','-l','-r',str(source),'-Y',' or '.join(selected),'-T','pdml'],stdout=subprocess.PIPE,stderr=err)
   root=None;count=0
   for ev,p in ET.iterparse(proc.stdout,events=('start','end')):
    if root is None:root=p
    if ev=='end' and p.tag=='packet':
     ingest(db,p);count+=1;p.clear();root.clear()
     if count%500==0:putmeta(db,'intelligence_records',count);db.commit()
   if proc.wait():raise RuntimeError('Protocol extraction failed; see intelligence-tshark.log')
  after=source.stat()
  if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise RuntimeError('Source changed during extraction')
  putmeta(db,'intelligence_status','Complete');putmeta(db,'intelligence_version',VERSION);putmeta(db,'intelligence_records',count);db.commit()
 except Exception as exc:putmeta(db,'intelligence_status','Partial/failed: '+str(exc));db.commit();raise
 finally:
  if proc:
   if proc.poll() is None:proc.kill();proc.wait()
   proc.stdout.close()
  db.close()

def scope(db,q,alias='e'):
 if q.get('scope','capture')=='vessel':return f'{alias}.frame IN (SELECT frame FROM links WHERE vessel_id=?)',[int(q.get('vessel',0))]
 if q.get('scope')=='satellite':
  from satellite_profiles import profile
  p=profile(db,q.get('satellite',''));ids=[-m['id'] for m in p['mappings']]
  return (f"{alias}.frame IN (SELECT frame FROM links WHERE session_id IN ({','.join('?' for _ in ids)}))",ids) if ids else ('0',[])
 return '1',[]

def listing(db,q):
 state=db.execute("SELECT value FROM meta WHERE key='intelligence_status'").fetchone();status=json.loads(state[0]) if state else 'Pending background indexing'
 if not db.execute("SELECT 1 FROM sqlite_master WHERE name='intelligence_events'").fetchone():return {'status':status,'rows':[],'total':0,'audio':[]}
 where,args=scope(db,q);where+=' AND e.category=?';args.append(q.get('kind','stun'))
 if q.get('q'):where+=' AND (e.summary LIKE ? OR e.raw LIKE ? OR e.src LIKE ? OR e.dst LIKE ?)';args+=['%'+q['q']+'%']*4
 total=db.execute('SELECT count(*) FROM intelligence_events e WHERE '+where,args).fetchone()[0]
 result=[dict(r) for r in db.execute('SELECT e.* FROM intelligence_events e WHERE '+where+' ORDER BY frame LIMIT 100 OFFSET ?',args+[max(0,int(q.get('offset',0)))])]
 for r in result:r['raw']=json.loads(r['raw'])
 audio=[]
 if q.get('kind')=='voip':
  w,a=scope(db,q,'r');audio=[dict(r) for r in db.execute('SELECT stream,src,dst,sport,dport,ssrc,pt,count(*) packets,min(t) first_seen,max(t) last_seen FROM intelligence_rtp r WHERE '+w+' GROUP BY stream ORDER BY packets DESC LIMIT 100',a)]
 return {'status':status,'rows':result,'total':total,'audio':audio,'scope':q.get('scope','capture'),'interpretation':'Decoded fields are observations, not proof of a leak, successful call, camera identity or exclusive subscriber ownership. Satellite scope covers existing mapped frames only.'}

def wav(db,q):
 import io,wave,struct
 w,args=scope(db,q,'r');cur=db.execute('SELECT * FROM intelligence_rtp r WHERE '+w+' AND stream=? ORDER BY t,frame',args+[q.get('stream','')]);out=io.BytesIO();seen=set();origin=None;written=0;limit=8000*300
 with wave.open(out,'wb') as f:
  f.setnchannels(1);f.setsampwidth(2);f.setframerate(8000)
  for r in cur:
   marker=(r['seq'],r['rtp_time'])
   if marker in seen:continue
   seen.add(marker)
   if origin is None:origin=r['rtp_time']
   target=(r['rtp_time']-origin)&0xffffffff
   if target>=limit:break
   if target<written:continue
   f.writeframesraw(b'\0\0'*(target-written));samples=[]
   for b in r['payload'][:limit-target]:
    if r['pt']==0:
     u=(~b)&255;n=((u&15)<<3)+132;n<<=(u&112)>>4;n=(132-n) if u&128 else (n-132)
    else:
     a=b^85;n=(a&15)<<4;seg=(a&112)>>4;n=n+8 if seg==0 else (n+264)<<(seg-1);n=n if a&128 else -n
    samples.append(n)
   f.writeframesraw(struct.pack('<'+'h'*len(samples),*samples));written=target+len(samples)
 if origin is None:raise ValueError('No supported audio in this scope')
 return out.getvalue()

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('database');build(p.parse_args().database)
