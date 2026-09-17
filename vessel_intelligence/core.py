"""Evidence-first streaming PCAP analysis. Python 3.11+, Wireshark tshark."""
from __future__ import annotations
import argparse, collections, csv, hashlib, ipaddress, json, os, pathlib, re, shutil, sqlite3, subprocess, sys, time
import xml.etree.ElementTree as ET
from decimal import Decimal

ROOT=pathlib.Path(__file__).resolve().parent
def dumps(x): return json.dumps(x,ensure_ascii=False,separators=(',',':'))
def ns(x): return int(Decimal(str(x))*1000000000)
def first(d,k,default=''): return d.get(k,[default])[0]
def num(x,default=0):
 try:return int(x,0) if str(x).startswith('0x') else int(x)
 except (ValueError,TypeError):return default
def norm(k):return k.replace('-','_')
def executable(name):
 p=shutil.which(name) or str(pathlib.Path(os.environ.get('ProgramFiles','C:/Program Files'))/'Wireshark'/f'{name}.exe')
 if not pathlib.Path(p).exists():raise RuntimeError(f'{name} is required. Install Wireshark or add it to PATH.')
 return p

SCHEMA='''
CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT);
CREATE TABLE vessels(id INTEGER PRIMARY KEY,name TEXT,username TEXT,calling_station TEXT,nas TEXT,imo TEXT,mmsi TEXT,confidence TEXT,reason TEXT,evidence TEXT);
CREATE TABLE radius(frame INTEGER PRIMARY KEY,t INTEGER,src TEXT,dst TEXT,context TEXT,code TEXT,status TEXT,username TEXT,calling_station TEXT,called_station TEXT,nas TEXT,nas_name TEXT,acct_id TEXT,ips TEXT,age INTEGER,delay INTEGER,event_time TEXT,input_bytes INTEGER,output_bytes INTEGER,raw TEXT,vessel_id INTEGER,session_id INTEGER);
CREATE TABLE sessions(id INTEGER PRIMARY KEY,vessel_id INTEGER,acct_id TEXT,username TEXT,calling_station TEXT,nas TEXT,context TEXT,start INTEGER,end INTEGER,estimated_start INTEGER,actual_start INTEGER,actual_stop INTEGER,input_bytes INTEGER,output_bytes INTEGER,counter_input_delta INTEGER,counter_output_delta INTEGER,confidence TEXT,reason TEXT,frames TEXT);
CREATE TABLE assignments(id INTEGER PRIMARY KEY,session_id INTEGER,vessel_id INTEGER,ip TEXT,context TEXT,start INTEGER,end INTEGER,confidence TEXT,reason TEXT,frames TEXT);
CREATE TABLE packets(frame INTEGER PRIMARY KEY,t INTEGER,length INTEGER,captured_length INTEGER,src TEXT,sport TEXT,dst TEXT,dport TEXT,transport TEXT,application TEXT,protocols TEXT,context TEXT,raw TEXT);
CREATE TABLE links(frame INTEGER,vessel_id INTEGER,session_id INTEGER,assignment_id INTEGER,direction TEXT,scope TEXT,confidence TEXT,reason TEXT,flow_id INTEGER,PRIMARY KEY(frame,vessel_id,session_id));
CREATE TABLE flows(id INTEGER PRIMARY KEY,vessel_id INTEGER,session_id INTEGER,key TEXT,local_ip TEXT,local_port TEXT,remote_ip TEXT,remote_port TEXT,transport TEXT,application TEXT,first_seen INTEGER,last_seen INTEGER,packets INTEGER,bytes INTEGER,bytes_up INTEGER,bytes_down INTEGER,bytes_internal INTEGER,domain TEXT,service TEXT,confidence TEXT,reason TEXT,evidence TEXT);
CREATE TABLE dns(id INTEGER PRIMARY KEY,frame INTEGER,t INTEGER,vessel_id INTEGER,session_id INTEGER,flow_id INTEGER,query TEXT,answer_ip TEXT,record_type TEXT,ttl INTEGER,is_response INTEGER,response_to TEXT,reason TEXT);
CREATE TABLE tls(id INTEGER PRIMARY KEY,frame INTEGER,t INTEGER,vessel_id INTEGER,session_id INTEGER,flow_id INTEGER,sni TEXT,version TEXT,alpn TEXT,certificate_cn TEXT,certificate_san TEXT,issuer TEXT,quic_id TEXT,raw TEXT);
CREATE TABLE audit(id INTEGER PRIMARY KEY,frame INTEGER,t INTEGER,kind TEXT,detail TEXT);
CREATE TABLE external(vessel_id INTEGER PRIMARY KEY,source TEXT,url TEXT,verified_at TEXT,information TEXT,match_basis TEXT);
CREATE TABLE capture_protocols(protocol TEXT PRIMARY KEY,packets INTEGER,bytes INTEGER);
CREATE TABLE address_visibility(ip TEXT PRIMARY KEY,header_packets INTEGER,first_frame INTEGER,last_frame INTEGER);
CREATE INDEX radius_v ON radius(vessel_id); CREATE INDEX sessions_v ON sessions(vessel_id);
CREATE INDEX assign_ip ON assignments(ip,start,end); CREATE INDEX links_v ON links(vessel_id,frame);
CREATE INDEX packets_t ON packets(t); CREATE INDEX flows_v ON flows(vessel_id);
CREATE INDEX dns_match ON dns(vessel_id,session_id,answer_ip,t); CREATE INDEX links_flow ON links(flow_id);
CREATE INDEX dns_vquery ON dns(vessel_id,query); CREATE INDEX flows_vdomain ON flows(vessel_id,domain); CREATE INDEX flows_session ON flows(session_id);
'''
from satellite import SCHEMA as SATELLITE_SCHEMA
SCHEMA += SATELLITE_SCHEMA
def dbopen(path):
 db=sqlite3.connect(path);db.row_factory=sqlite3.Row
 db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA cache_size=-32768');db.execute('PRAGMA temp_store=FILE')
 return db
def putmeta(db,k,v):db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',(k,dumps(v)))
def progress(stage,**kw):print(dumps(dict(stage=stage,**kw)),flush=True)
def field_inventory(tshark):
 out=subprocess.check_output([tshark,'-G','fields'],text=True,encoding='utf8',errors='replace')
 return {l.split('\t')[2] for l in out.splitlines() if l.startswith('F\t') and len(l.split('\t'))>2}

def parse_radius(path,db):
 """Keep all RADIUS field attributes, including unknown/vendor AVPs and raw hex."""
 root=None; count=0
 for event,p in ET.iterparse(path,events=('start','end')):
  if root is None:root=p
  if event!='end' or p.tag!='packet':continue
  d=collections.defaultdict(list);raw=[]
  for f in p.iter('field'):
   k=f.get('name','');d[norm(k)].append(f.get('show',''))
   if k.startswith('radius.'):raw.append(dict(f.attrib))
  g=lambda k:first(d,norm(k))
  # Select innermost addresses even in mixed IPv4/IPv6 encapsulation.
  source,_,destination,_,_,_,ctx=endpoints(d)
  ips=[]
  for k in ('radius.Framed_IP_Address','radius.Framed_IPv6_Address'):
   for val in d.get(k,[]):
    try:
     a=ipaddress.ip_address(val)
     if not a.is_unspecified and str(a) not in ('255.255.255.254','255.255.255.255'):ips.append(str(a))
    except ValueError:pass
  # Prefix attributes are byte-encoded: reserved byte, prefix length, prefix bytes.
  for val in d.get('radius.Framed_IPv6_Prefix',[]):
   try:
    b=bytes.fromhex(val.replace(':','')); plen=b[1]
    if plen>128:continue
    network=ipaddress.IPv6Network((int.from_bytes(b[2:].ljust(16,b'\0'),'big'),plen),strict=False)
    iid=g('radius.Framed_Interface_Id').replace(':','')
    if plen==64 and len(iid)==16:ips.append(str(ipaddress.IPv6Address(int(network.network_address)|int(iid,16))))
    else:ips.append(str(network))
   except (ValueError,IndexError):pass
  def counter(k):
   v=g('radius.Acct_'+k+'_Octets'); hi=g('radius.Acct_'+k+'_Gigawords')
   return num(v)+(num(hi)<<32) if v else None
  row=(num(g('frame.number')),ns(g('frame.time_epoch')),source,destination,ctx,g('radius.code'),g('radius.Acct_Status_Type'),g('radius.User_Name'),g('radius.Calling_Station_Id'),g('radius.Called_Station_Id'),g('radius.NAS_IP_Address') or g('radius.NAS_IPv6_Address'),g('radius.NAS_Identifier'),g('radius.Acct_Session_Id'),dumps(sorted(set(ips))),num(g('radius.Acct_Session_Time'),-1),num(g('radius.Acct_Delay_Time')),g('radius.Event_Timestamp'),counter('Input'),counter('Output'),dumps(raw),None,None)
  db.execute('INSERT INTO radius VALUES ('+','.join('?'*22)+')',row);count+=1
  p.clear();root.clear()
 db.commit();return count

def build_sessions(db):
 """Site candidates require NAS evidence; usernames alone remain unresolved identities."""
 groups={};sessiongroups=collections.defaultdict(list);requests={};duplicates=[]
 for r in db.execute("SELECT * FROM radius WHERE username!='' OR nas_name!='' ORDER BY t,frame").fetchall():
  key=(r['nas_name'],r['nas'],r['context']) if r['nas_name'] and r['nas'] else ('unresolved',r['username'],r['calling_station'],r['nas'],r['context'])
  if key not in groups:
   name=r['nas_name'] or ('Unresolved account: '+(r['username'] or r['calling_station']))
   corroborated=r['nas_name'] and r['nas_name'].casefold()==r['called_station'].casefold()
   reason=('Probable site/vessel label: NAS-Identifier and Called-Station-Id agree; NAS-IP and tunnel namespace group subscriber accounts. Physical vessel identity remains unverified.' if corroborated else 'NAS/site or account identity only; insufficient evidence to establish a physical vessel.')
   evidence=[{'frame':r['frame'],'NAS-Identifier':r['nas_name'],'NAS-IP-Address':r['nas'],'Called-Station-Id':r['called_station'],'username':r['username'],'context':r['context']}]
   imo='';mmsi=''
   for val in (r['nas_name'],r['username'],r['called_station']):
    m=re.search(r'\bIMO[ _:-]*(\d{7})\b',val,re.I)
    if m and sum(int(c)*(7-i) for i,c in enumerate(m[1][:6]))%10==int(m[1][-1]):imo=m[1]
    m=re.search(r'\bMMSI[ _:-]*(\d{9})\b',val,re.I)
    if m:mmsi=m[1]
   cur=db.execute('INSERT INTO vessels VALUES(NULL,?,?,?,?,?,?,?,?,?)',(name,r['username'],r['calling_station'],r['nas'],imo,mmsi,'Medium' if corroborated else 'Low',reason,dumps(evidence)));groups[key]=cur.lastrowid
  vid=groups[key];db.execute('UPDATE radius SET vessel_id=? WHERE frame=?',(vid,r['frame']))
  if r['code']=='4' and r['acct_id'] and r['status'] in ('1','2','3'):
   raw={f.get('name'):f.get('show','') for f in json.loads(r['raw'])};auth=raw.get('radius.authenticator');rid=raw.get('radius.id')
   fingerprint=(r['src'],r['dst'],r['context'],rid,auth)
   if auth and rid and fingerprint in requests:duplicates.append((r['frame'],requests[fingerprint]));continue
   if auth and rid:requests[fingerprint]=r['frame']
   sessiongroups[(vid,r['nas'],r['context'],r['acct_id'],r['username'],r['calling_station'])].append(r)
 for key,records in sessiongroups.items():
  # Split reused session IDs on fresh Starts or decreasing accounting uptime.
  batches=[];batch=[]
  resets=[x[0] for x in db.execute("SELECT t FROM radius WHERE nas=? AND context=? AND status IN ('7','8')",(key[1],key[2]))]
  for r in records:
   if batch and ((r['status']=='1' and batch[-1]['status']!='1') or (r['age']>=0 and batch[-1]['age']>=0 and r['age']<batch[-1]['age']) or batch[-1]['status']=='2' or any(batch[-1]['t']<t<=r['t'] for t in resets)):
    batches.append(batch);batch=[]
   batch.append(r)
  if batch:batches.append(batch)
  for batch in batches:
   vid,nas,ctx,acct,user,calling=key
   # Delay correction is explicit; packet timestamps are always retained untouched.
   event=lambda r:r['t']-max(0,r['delay'])*1000000000
   start=min(map(event,batch));end=max(map(event,batch));starts=[event(r) for r in batch if r['status']=='1'];stops=[event(r) for r in batch if r['status']=='2']
   estimated=[event(r)-r['age']*1000000000 for r in batch if r['age']>=0]
   def counts(k):
    vals=[r[k] for r in batch if r[k] is not None]
    return (vals[-1],vals[-1]-vals[0] if len(vals)>1 and all(b>=a for a,b in zip(vals,vals[1:])) else None) if vals else (None,None)
   ib,di=counts('input_bytes');ob,do=counts('output_bytes')
   reason='Strict assignment windows span observations of the same IP within this session. Uptime estimates session start, not IP assignment start. No extension before first IP observation or beyond last accounting evidence.'
   frames=[r['frame'] for r in batch]
   sid=db.execute('INSERT INTO sessions VALUES(NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(vid,acct,user,calling,nas,ctx,start,end,min(estimated) if estimated else None,min(starts) if starts else None,max(stops) if stops else None,ib,ob,di,do,'High' if starts and stops else 'Medium',reason,dumps(frames))).lastrowid
   db.executemany('UPDATE radius SET session_id=? WHERE frame=?',[(sid,r['frame']) for r in batch])
   runs=[];run=[];previous=None
   for r in batch:
    ips=tuple(json.loads(r['ips']))
    if ips!=previous and run:runs.append((previous,run));run=[]
    run.append(r);previous=ips
   if run:runs.append((previous,run))
   for ips,run in runs:
    for ip in ips:
     a=min(map(event,run));b=max(map(event,run))
     reason2='Direct RADIUS assignment; bounded by same-address observations, continuity within that interval is inferred.' if b>a else 'Single accounting observation: assignment valid only at the observed event instant; no traffic interval inferred.'
     db.execute('INSERT INTO assignments VALUES(NULL,?,?,?,?,?,?,?,?,?)',(sid,vid,ip,ctx,a,b,'Medium' if b>a else 'High',reason2,dumps([r['frame'] for r in run])))
 for duplicate,original in duplicates:
  db.execute('UPDATE radius SET session_id=(SELECT session_id FROM radius WHERE frame=?) WHERE frame=?',(original,duplicate))
 link_radius_responses(db)
 db.commit()

def link_radius_responses(db):
 for r in db.execute('SELECT * FROM radius WHERE vessel_id IS NULL').fetchall():
  refs=[num(f.get('show')) for f in json.loads(r['raw']) if f.get('name')=='radius.reqframe']
  if len(set(refs))==1:
   req=db.execute('SELECT * FROM radius WHERE frame=?',(refs[0],)).fetchone()
   if req and req['vessel_id'] and req['src']==r['dst'] and req['dst']==r['src'] and req['context']==r['context']:
    db.execute('UPDATE radius SET vessel_id=?,session_id=? WHERE frame=?',(req['vessel_id'],req['session_id'],r['frame']))

FIELDS='''frame.number frame.time_epoch frame.len frame.cap_len frame.protocols frame.interface_id ip.src ip.dst ipv6.src ipv6.dst tcp.srcport tcp.dstport udp.srcport udp.dstport tcp.stream udp.stream dns.id dns.flags.response dns.flags.rcode dns.qry.name dns.qry.type dns.a dns.aaaa dns.resp.ttl dns.resp.name dns.resp.type dns.cname dns.response_to dns.response_in tls.handshake.extensions_server_name tls.handshake.version tls.record.version tls.handshake.extensions.supported_version tls.handshake.extensions_alpn_str x509sat.uTF8String x509sat.printableString x509ce.dNSName http.host http.request.method http.request.uri http2.headers.authority http3.headers.authority quic.dcid quic.scid quic.connection.number l2tp.tunnel l2tp.session tcp.flags.syn tcp.flags.ack'''.split()
FIELDS += ['tls.handshake.certificate','frame.comment','tcp.analysis.retransmission','tcp.analysis.lost_segment','tcp.analysis.out_of_order','rtp.ssrc','rtp.seq','rtp.timestamp','stun.type','stun.id']

def certificate(d):
 cn='';issuer='';san=','.join(d.get('x509ce.dNSName',[]))
 try:
  from cryptography import x509
  from cryptography.x509.oid import NameOID
  raw=first(d,'tls.handshake.certificate')
  if raw:
   cert=x509.load_der_x509_certificate(bytes.fromhex(raw.replace(':','')))
   cn=','.join(a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME));issuer=cert.issuer.rfc4514_string()
   try:san=','.join(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
   except x509.ExtensionNotFound:pass
 except (ImportError,ValueError):pass
 return cn,san,issuer

class Matcher:
 def __init__(self,rows):
  self.exact=collections.defaultdict(list);self.networks=[]
  for r in rows:
   if '/' in r['ip']:self.networks.append((ipaddress.ip_network(r['ip']),dict(r)))
   else:self.exact[r['ip']].append(dict(r))
 def lookup(self,ip,t,ctx):
  candidates=list(self.exact.get(ip,[]))
  if self.networks:
   try:candidates += [r for net,r in self.networks if ipaddress.ip_address(ip) in net]
   except ValueError:pass
  matches=[r for r in candidates if r['start']<=t<=r['end'] and r['context']==ctx]
  # Multiple sessions claiming the same address in a namespace are ambiguous even for one vessel.
  unique={r['session_id']:r for r in matches}
  return list(unique.values())

def endpoints(d):
 ps=first(d,'frame.protocols').split(':')
 # ICMP error quotations are evidence about a different packet, not encapsulated user traffic.
 for i,p in enumerate(ps):
  if p in ('icmp','icmpv6'):
   ps=ps[:i+1];break
 family=[p for p in ps if p in ('ip','ipv6')]
 fam=family[-1] if family else 'ip';sf=d.get(fam+'.src',[]);df=d.get(fam+'.dst',[])
 outer=family[0] if family else 'ip';osrc=first(d,outer+'.src');odst=first(d,outer+'.dst')
 ctx='|'.join(sorted([osrc,odst])) if len(family)>1 else ''
 idx=sum(p==fam for p in family)-1
 src=sf[idx] if sf and 0<=idx<len(sf) else '';dst=df[idx] if df and 0<=idx<len(df) else ''
 # Use the innermost transport after the innermost network header.
 tail=ps[max(i for i,p in enumerate(ps) if p in ('ip','ipv6'))+1:] if family else ps
 transport=next((p.upper() for p in tail if p in ('tcp','udp','sctp','icmp','icmpv6','esp','gre')),'OTHER')
 sport=(d.get(transport.lower()+'.srcport') or [''])[-1];dport=(d.get(transport.lower()+'.dstport') or [''])[-1]
 app=next((p for p in reversed(tail) if p not in ('data','_ws.malformed','tcp.segments','tls.segments','data-text-lines') and not p.startswith(('x509','pkcs'))),transport.lower())
 return src,sport,dst,dport,transport,app,ctx

def classify(domain,application):
 host=domain.lower().rstrip('.').split(':')[0]
 rules={'YouTube':['youtube.com','youtu.be','googlevideo.com','ytimg.com'],'Instagram':['instagram.com','cdninstagram.com'],'WhatsApp':['whatsapp.net','whatsapp.com'],'Facebook':['facebook.com','fbcdn.net','fb.com'],'Teams':['teams.microsoft.com','teams.live.com'],'Zoom':['zoom.us','zoom.com'],'Netflix':['netflix.com','nflxvideo.net','nflximg.net'],'TikTok':['tiktok.com','tiktokcdn.com','byteoversea.com'],'Telegram':['telegram.org','t.me'],'Microsoft':['microsoft.com','office.com','office365.com','windows.net','live.com','outlook.com'],'Google':['google.com','googleapis.com','gstatic.com','googleusercontent.com'],'Apple':['apple.com','icloud.com','mzstatic.com'],'AWS':['amazonaws.com'],'Cloudflare':['cloudflare.com','cloudflare-dns.com']}
 for name,suffixes in rules.items():
  if any(host==s or host.endswith('.'+s) for s in suffixes):return name
 if application in ('smtp','imap','pop','imf'):return 'Email'
 if application in ('openvpn','wireguard','wg','isakmp','esp'):return 'VPN protocol'
 if host:return 'Web / named endpoint'
 return 'Unknown'

def traffic(db,pcap,tshark,total,keylog=None):
 from satellite import SCHEMA as SAT_SCHEMA
 db.executescript(SAT_SCHEMA)
 satcursor=iter(db.execute('SELECT sp.frame,m.* FROM satellite_packets sp JOIN satellite_mapping m ON m.id=sp.mapping_id ORDER BY sp.frame'))
 satnext=next(satcursor,None)
 available=field_inventory(tshark);fields=[f for f in FIELDS if f in available];putmeta(db,'unavailable_fields',sorted(set(FIELDS)-available))
 cmd=[tshark,'-n','-l','-r',str(pcap),'-T','fields','-E','separator=/t','-E','quote=d','-E','occurrence=a','-E','aggregator=|']
 if keylog:cmd+=['-o','tls.keylog_file:'+str(pathlib.Path(keylog).resolve())]
 for f in fields:cmd+=['-e',f]
 matcher=Matcher(db.execute('SELECT * FROM assignments'));counts=collections.Counter();sizes=collections.Counter();stats=collections.Counter();visibility={ip:[0,None,None] for ip in matcher.exact};begin=time.monotonic();lo=None;hi=None
 err=open(db.execute("SELECT value FROM meta WHERE key='log_path'").fetchone()[0].strip('"'),'w',encoding='utf8')
 proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=err,text=True,encoding='utf8',errors='replace',bufsize=1024*1024)
 try:
  for row in csv.reader(proc.stdout,delimiter='\t',quotechar='"'):
   d={k:v.split('|') for k,v in zip(fields,row) if v};frame=num(first(d,'frame.number'));length=num(first(d,'frame.len'));caplen=num(first(d,'frame.cap_len'))
   if not first(d,'frame.time_epoch'):
    stats['packets']+=1;stats['untimestamped_records']+=1;stats['unattributed_packets']+=1;stats['wire_bytes']+=length;stats['captured_bytes']+=caplen;counts['untimestamped metadata']+=1;sizes['untimestamped metadata']+=length
    db.execute('INSERT INTO audit VALUES(NULL,?,?,?,?)',(frame,None,'missing_capture_timestamp',dumps({'reason':'Metadata record has no timestamp; not assigned to a vessel or session.','raw':d})));continue
   t=ns(first(d,'frame.time_epoch'));lo=t if lo is None else min(lo,t);hi=t if hi is None else max(hi,t)
   src,sp,dst,dp,tr,app,ctx=endpoints(d);stats['packets']+=1;stats['wire_bytes']+=length;stats['captured_bytes']+=caplen;counts[app]+=1;sizes[app]+=length
   for ip in set(d.get('ip.src',[])+d.get('ip.dst',[])+d.get('ipv6.src',[])+d.get('ipv6.dst',[])):
    if ip in visibility:
     v=visibility[ip];v[0]+=1;v[1]=frame if v[1] is None else v[1];v[2]=frame
   sm=matcher.lookup(src,t,ctx);dm=matcher.lookup(dst,t,ctx)
   ambiguous=len(sm)>1 or len(dm)>1
   if ambiguous:
    stats['ambiguous_packets']+=1;db.execute('INSERT INTO audit VALUES(NULL,?,?,?,?)',(frame,t,'ambiguous_assignment',dumps({'src':src,'dst':dst,'session_ids':[x['session_id'] for x in sm+dm]})));sm=[];dm=[]
   selected={r['session_id']:r for r in sm+dm}
   if not selected and (src in matcher.exact or dst in matcher.exact):
    candidates=matcher.exact.get(src,[])+matcher.exact.get(dst,[])
    same_context=[a for a in candidates if a['context']==ctx]
    kind='outside_assignment_window' if same_context else 'different_network_namespace'
    db.execute('INSERT INTO audit VALUES(NULL,?,?,?,?)',(frame,t,kind,dumps({'src':src,'dst':dst,'context':ctx,'candidate_session_ids':[a['session_id'] for a in candidates],'reason':'Address string alone is insufficient; no session attribution made.'})))
   while satnext is not None and satnext['frame']<frame:satnext=next(satcursor,None)
   sat=satnext if satnext is not None and satnext['frame']==frame and t>=satnext['start_ns'] else None
   if not selected and not ambiguous and sat is not None:
    selected={-sat['id']:{'id':0,'vessel_id':sat['vessel_id'],'confidence':'Medium','reason':sat['reason']}}
    stats['satellite_attributed_packets']+=1
   if selected:
    stats['correlated_packets']+=1
    db.execute('INSERT INTO packets VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',(frame,t,length,caplen,src,sp,dst,dp,tr,app,first(d,'frame.protocols'),ctx,dumps(d)))
    for sid,a in selected.items():
     isup=any(x['session_id']==sid for x in sm);internal=bool(sm and dm and sm[0]['vessel_id']==dm[0]['vessel_id'])
     # Internal packet appears once per vessel (retains both assignments in raw endpoints).
     if internal and sid!=sm[0]['session_id']:continue
     direction=(sat['direction'] if sid<0 else ('internal' if internal else ('upload' if isup else 'download')));scope='terminal bearer; individual subscriber unknown' if sid<0 else ('internal' if internal else 'external to observed assignment (NAT visibility unknown)')
     db.execute('INSERT INTO links VALUES(?,?,?,?,?,?,?,?,NULL)',(frame,a['vessel_id'],sid,a['id'],direction,scope,a['confidence'],a['reason']+' Direction is relative to the observed assigned IP, not a claim about a hidden host.'))
    for diagnostic in ('tcp.analysis.retransmission','tcp.analysis.lost_segment','tcp.analysis.out_of_order'):
     if diagnostic in d:
      for a in selected.values():db.execute('INSERT INTO diagnostics VALUES(?,?,?,?)',(frame,a['vessel_id'],diagnostic,dumps(d)))
   else:stats['unattributed_packets']+=1
   if frame%10000==0:
    db.commit();progress('traffic',packets_processed=frame,percent=round(frame/total*100,2) if total else None,current_protocol=app,correlated_packets=stats['correlated_packets'],elapsed_seconds=round(time.monotonic()-begin,1))
  if proc.wait()!=0:raise RuntimeError('tshark failed; see tshark.log')
 finally:
  if proc.poll() is None:proc.kill();proc.wait()
  proc.stdout.close()
  err.close()
 db.executemany('INSERT INTO address_visibility VALUES(?,?,?,?)',[(ip,*v) for ip,v in visibility.items()]);db.executemany('INSERT INTO capture_protocols VALUES(?,?,?)',[(k,v,sizes[k]) for k,v in counts.items()]);putmeta(db,'capture_stats',dict(stats));putmeta(db,'capture_start_ns',lo);putmeta(db,'capture_end_ns',hi);putmeta(db,'traffic_seconds',time.monotonic()-begin);db.commit()

def correlate(db):
 # Disk-backed flow keys avoid keeping packet or flow collections in RAM.
 db.execute('CREATE UNIQUE INDEX IF NOT EXISTS flow_key ON flows(vessel_id,session_id,key)')
 db.execute('CREATE TABLE IF NOT EXISTS quic_alias(vessel_id INTEGER,session_id INTEGER,udp_stream TEXT,connection TEXT, UNIQUE(vessel_id,session_id,udp_stream,connection))')
 q='SELECT p.*,l.vessel_id,l.session_id,l.direction FROM packets p JOIN links l ON l.frame=p.frame ORDER BY p.t,p.frame'
 n=0
 for p in db.execute(q):
  d=json.loads(p['raw']);up=p['direction']=='upload';internal=p['direction']=='internal';lip,lp,rip,rp=(p['src'],p['sport'],p['dst'],p['dport']) if up or internal else (p['dst'],p['dport'],p['src'],p['sport'])
  # tshark stream/QUIC connection IDs are capture-scoped; always additionally scoped by RADIUS session.
  stream=(d.get(p['transport'].lower()+'.stream') or [''])[-1];quic=first(d,'quic.connection.number')
  vid,sid=p['vessel_id'],p['session_id'];length=p['length'];bu=length if up else 0;bd=length if p['direction']=='download' else 0;bi=length if internal else 0
  if p['transport']=='UDP' and stream:
   if quic:db.execute('INSERT OR IGNORE INTO quic_alias VALUES(?,?,?,?)',(vid,sid,stream,quic))
   else:
    aliases=db.execute('SELECT connection FROM quic_alias WHERE vessel_id=? AND session_id=? AND udp_stream=?',(vid,sid,stream)).fetchall()
    if len(aliases)==1:quic=aliases[0][0]
  key=dumps(['quic',quic]) if quic else dumps([p['transport'],stream,lip,lp,rip,rp])
  db.execute('INSERT INTO flows VALUES(NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(vessel_id,session_id,key) DO UPDATE SET last_seen=max(last_seen,excluded.last_seen),packets=packets+1,bytes=bytes+excluded.bytes,bytes_up=bytes_up+excluded.bytes_up,bytes_down=bytes_down+excluded.bytes_down,bytes_internal=bytes_internal+excluded.bytes_internal', (vid,sid,key,lip,lp,rip,rp,p['transport'],p['application'],p['t'],p['t'],1,length,bu,bd,bi,'','Unknown','Low','No application identity evidence','[]'))
  fid=db.execute('SELECT id FROM flows WHERE vessel_id=? AND session_id=? AND key=?',(vid,sid,key)).fetchone()[0];db.execute('UPDATE links SET flow_id=? WHERE frame=? AND vessel_id=? AND session_id=?',(fid,p['frame'],vid,sid))
  if p['application'] not in ('tcp','udp','data','ip','ipv6'):
   db.execute('UPDATE flows SET application=? WHERE id=?',(p['application'],fid))
  if 'dns' in p['protocols'].split(':'):
   queries=d.get('dns.qry.name',[]);answers=d.get('dns.a',[])+d.get('dns.aaaa',[]);ttls=[num(v) for v in d.get('dns.resp.ttl',[])];response=first(d,'dns.flags.response') in ('1','True');valid=response and first(d,'dns.flags.rcode') in ('0','')
   # Multiple questions/answer owners cannot safely be zipped from flat fields.
   safe=len(queries)==1 and valid and bool(first(d,'dns.response_to'))
   for query in queries or ['']:
    for answer in answers or ['']:
     why='Single question, tshark-linked response; minimum response TTL conservatively bounds later reuse.' if safe else 'Raw DNS observation only; unanswered, unsolicited, failed, or multi-question response is not used for destination inference.'
     db.execute('INSERT INTO dns VALUES(NULL,?,?,?,?,?,?,?,?,?,?,?,?)',(p['frame'],p['t'],vid,sid,fid,query,answer,','.join(d.get('dns.qry.type',[])),min(ttls) if ttls and safe else 0,int(response),first(d,'dns.response_to'),why))
  sni=d.get('tls.handshake.extensions_server_name',[]);http=d.get('http.host',[])+d.get('http2.headers.authority',[])+d.get('http3.headers.authority',[])
  if sni or any(k.startswith(('tls.','x509','quic.')) for k in d):
   cn,san,issuer=certificate(d)
   db.execute('INSERT INTO tls VALUES(NULL,?,?,?,?,?,?,?,?,?,?,?,?,?)',(p['frame'],p['t'],vid,sid,fid,','.join(sni),','.join(d.get('tls.handshake.extensions.supported_version',[]) or d.get('tls.handshake.version',[]) or d.get('tls.record.version',[])),','.join(d.get('tls.handshake.extensions_alpn_str',[])),cn,san,issuer,','.join(d.get('quic.dcid',[])+d.get('quic.scid',[])),dumps({k:v for k,v in d.items() if k.startswith(('tls.','x509','quic.'))})))
  if sni or http:
   ev=json.loads(db.execute('SELECT evidence FROM flows WHERE id=?',(fid,)).fetchone()[0]);ev.append({'frame':p['frame'],'kind':'TLS SNI' if sni else 'HTTP authority','domains':sni or http})
   db.execute('UPDATE flows SET evidence=? WHERE id=?',(dumps(ev),fid))
  n+=1
  if n%10000==0:db.commit();progress('flow_correlation',linked_packets=n)
 db.commit()
 for f in db.execute('SELECT * FROM flows'):
  ev=json.loads(f['evidence']);hosts={h.lower().rstrip('.') for e in ev for h in e.get('domains',[])}
  dnsrows=db.execute('SELECT * FROM dns WHERE vessel_id=? AND session_id=? AND answer_ip=? AND is_response=1 AND ttl>0 AND t<=? AND t+ttl*1000000000>=? ORDER BY t DESC LIMIT 50',(f['vessel_id'],f['session_id'],f['remote_ip'],f['first_seen'],f['first_seen'])).fetchall()
  # A query frame must itself belong to this same subscriber session.
  dnsrows=[r for r in dnsrows if db.execute('SELECT 1 FROM links WHERE frame=? AND vessel_id=? AND session_id=?',(num(r['response_to']),f['vessel_id'],f['session_id'])).fetchone()]
  dnsnames={r['query'].lower().rstrip('.') for r in dnsrows};confidence='Low';reason='No supported service identity; destination IP ownership is never used.'
  if hosts:
   confidence='High' if hosts & dnsnames else 'Medium';reason='DNS and application hostname agree within this session and TTL.' if hosts & dnsnames else 'Observed application hostname on this transport/QUIC stream; no matching DNS chain.'
  elif len(dnsnames)==1:
   hosts=dnsnames;confidence='Medium';reason='Earlier linked DNS response for this subscriber session and destination within TTL; shared hosting remains possible.'
  elif len(dnsnames)>1:reason='Multiple DNS names resolve to this destination; service is ambiguous without application metadata.'
  else:
   certs=db.execute("SELECT frame,certificate_cn,certificate_san FROM tls WHERE flow_id=? AND (certificate_cn!='' OR certificate_san!='')",(f['id'],)).fetchall()
   names={h.lower().removeprefix('*.') for r in certs for h in (r['certificate_san'] or r['certificate_cn']).split(',') if h}
   if names and len({classify(h,f['application']) for h in names})==1:
    hosts=names;confidence='Medium';reason='Observed certificate names support endpoint family only, not a specific encrypted request.'
    ev.extend({'frame':r['frame'],'kind':'Certificate names','cn':r['certificate_cn'],'san':r['certificate_san']} for r in certs)
  for r in dnsrows:ev.append({'frame':r['frame'],'query_frame':r['response_to'],'kind':'DNS response','domain':r['query'],'answer':r['answer_ip'],'ttl':r['ttl']})
  services={classify(h,f['application']) for h in hosts};service=next(iter(services)) if len(services)==1 else ('Mixed named endpoints' if services else classify('',f['application']))
  if not hosts and service!='Unknown':confidence='Medium';reason='Detected protocol supports category only.'
  db.execute('UPDATE flows SET domain=?,service=?,confidence=?,reason=?,evidence=? WHERE id=?',(', '.join(sorted(hosts)),service,confidence,reason,dumps(ev),f['id']))
 db.commit()

def analyze(args):
 pcap=pathlib.Path(args.pcap).resolve();out=pathlib.Path(args.out).resolve();out.mkdir(parents=True,exist_ok=True)
 dbpath=out/'analysis.sqlite'
 if dbpath.exists():raise RuntimeError(f'{dbpath} already exists. Choose a new --out directory to preserve evidence.')
 tshark=executable('tshark');start=time.monotonic();db=dbopen(dbpath);db.executescript(SCHEMA)
 putmeta(db,'status','processing');putmeta(db,'pcap',str(pcap));putmeta(db,'filename',pcap.name);putmeta(db,'size',pcap.stat().st_size);putmeta(db,'log_path',str(out/'tshark.log'));putmeta(db,'tshark_version',subprocess.check_output([tshark,'-v'],text=True).splitlines()[0]);db.commit()
 try:
  from capture_input import validate,fingerprint,VERSION
  validated=validate(pcap);initial_fingerprint=fingerprint(pcap)
  for k,v in validated.items():putmeta(db,k,v)
  putmeta(db,'parser_version',VERSION)
  progress('metadata',message='Capture content validated; counting packets and hashing capture with bounded buffers')
  info=subprocess.check_output([executable('capinfos'),'-T','-r','-c',str(pcap)],text=True,encoding='utf8',errors='replace');match=re.search(r'\t(\d+)\s*$',info.strip());total=int(match[1]) if match else 0
  putmeta(db,'expected_packets',total)
  h=hashlib.sha256()
  with pcap.open('rb') as fp:
   while chunk:=fp.read(8*1024*1024):h.update(chunk)
  putmeta(db,'sha256',h.hexdigest());progress('radius',message='Streaming all RADIUS attributes including vendor fields')
  radiuspath=out/'radius.pdml'
  if args.radius_xml:shutil.copyfile(args.radius_xml,radiuspath)
  else:
   with radiuspath.open('wb') as fp, (out/'radius-tshark.log').open('wb') as ep:
    subprocess.run([tshark,'-n','-r',str(pcap),'-Y','radius','-T','pdml'],stdout=fp,stderr=ep,check=True)
  nr=parse_radius(radiuspath,db);build_sessions(db)
  progress('mapping',radius_packets=nr,identified_vessel_candidates=db.execute('SELECT count(*) FROM vessels').fetchone()[0],identified_radius_sessions=db.execute('SELECT count(*) FROM sessions').fetchone()[0],correlated_ip_addresses=db.execute('SELECT count(DISTINCT ip) FROM assignments').fetchone()[0])
  from satellite import prepare
  progress('satellite',message='Indexing original custom blocks and packet annotations')
  try:prepare(db,pcap,radiuspath)
  except ValueError as exc:
   for table_name in ('telemetry','satellite_mapping','satellite_packets'):db.execute('DELETE FROM '+table_name)
   putmeta(db,'satellite_limitation',str(exc));db.commit()
  traffic(db,pcap,tshark,total,args.keylog);correlate(db)
  from diagnostics import build as build_diagnostics
  build_diagnostics(db)
  if fingerprint(pcap)!=initial_fingerprint:raise BlockingIOError('Source changed during analysis; results are invalid and must be retried')
  putmeta(db,'status','complete');putmeta(db,'elapsed_seconds',round(time.monotonic()-start,2));putmeta(db,'correlation_policy','Strict observed assignment intervals; matching encapsulation namespace; ambiguous sessions excluded. No NAT inference or uptime backfill. Additional terminal-bearer candidates use exact satellite session/stream annotations; negative session IDs refer to satellite mappings, not subscriber sessions.');db.commit();db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
  from reconstruction import build as reconstruct_content
  progress('reconstruction',message='Recovering visible HTTP, media, email and validated SMS content')
  try:reconstruct_content(dbpath,args.keylog)
  except Exception as content_error:putmeta(db,'reconstruction_status','Partial/failed: '+str(content_error));db.commit()
  from intelligence import build as build_intelligence
  progress('intelligence',message='Indexing STUN, signaling, subscriber and media evidence')
  try:build_intelligence(dbpath)
  except Exception as intelligence_error:putmeta(db,'intelligence_status','Partial/failed: '+str(intelligence_error));db.commit()
  from report import write_report
  write_report(db,out/'report.html');progress('complete',database=str(dbpath),dashboard=str(out/'report.html'),elapsed_seconds=round(time.monotonic()-start,1))
 except Exception as exc:putmeta(db,'status','failed');putmeta(db,'error',str(exc));db.commit();raise
 finally:db.close()

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('pcap');parser.add_argument('--out',required=True);parser.add_argument('--radius-xml',help='Reuse a complete tshark PDML extraction from exactly this capture');parser.add_argument('--keylog',help='Optional user-supplied TLS session key log');analyze(parser.parse_args())
