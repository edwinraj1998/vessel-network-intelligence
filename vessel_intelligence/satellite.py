"""Bounded block reader and explicit packet-comment to satellite-stream evidence."""
import struct,json,collections,xml.etree.ElementTree as ET
SCHEMA='''
CREATE TABLE IF NOT EXISTS telemetry(frame INTEGER,section INTEGER,kind TEXT,comm TEXT,stream TEXT,start_ns INTEGER,t_ns INTEGER,terminal TEXT,direction TEXT,raw TEXT);
CREATE TABLE IF NOT EXISTS satellite_mapping(id INTEGER PRIMARY KEY,vessel_id INTEGER,section INTEGER,comm TEXT,stream TEXT,terminal TEXT,direction TEXT,start_ns INTEGER,frames TEXT,radius_frames TEXT,reason TEXT);
CREATE TABLE IF NOT EXISTS satellite_packets(frame INTEGER PRIMARY KEY,mapping_id INTEGER,section INTEGER,comment TEXT);
CREATE TABLE IF NOT EXISTS diagnostics(frame INTEGER,vessel_id INTEGER,kind TEXT,raw TEXT);
'''
def blocks(path):
 with open(path,'rb') as f:
  if f.read(4)!=b'\x0a\x0d\x0d\x0a':return
  f.seek(0);endian='<';frame=0;section=-1
  while h:=f.read(8):
   if len(h)!=8:raise ValueError('Truncated PCAPNG header')
   extra=b''
   if h[:4]==b'\x0a\x0d\x0d\x0a':
    extra=f.read(4)
    if extra not in (b'\x4d\x3c\x2b\x1a',b'\x1a\x2b\x3c\x4d'):raise ValueError('Invalid PCAPNG byte order')
    endian='<' if extra==b'\x4d\x3c\x2b\x1a' else '>';section+=1
   typ,size=struct.unpack(endian+'II',h)
   if size<12 or size%4 or size>64*1024*1024:raise ValueError('Invalid PCAPNG block size')
   b=extra+f.read(size-8-len(extra))
   if len(b)!=size-8 or struct.unpack(endian+'I',b[-4:])[0]!=size:raise ValueError('Truncated PCAPNG block')
   if typ in (2,3,6,9,0xbad,0x40000bad):frame+=1
   elif typ not in (0x0a0d0d0a,1,4,5,10):raise ValueError(f'Unsupported block {typ:#x}; satellite indexing refused to preserve frame accuracy')
   yield frame,section,typ,b,endian
def object_json(text):
 decoder=json.JSONDecoder()
 for i,ch in enumerate(text):
  if ch=='{':
   try:r,_=decoder.raw_decode(text[i:])
   except ValueError:continue
   if isinstance(r,dict):return r
 return {}
def prepare(db,path,pdml):
 db.executescript(SCHEMA)
 for frame,section,typ,b,endian in blocks(path):
  if typ not in (0xbad,0x40000bad):continue
  r=object_json(b[4:-4].decode('utf8',errors='replace'))
  if r.get('type') not in ('stream','communication-session'):continue
  terminals=[(role,x) for role in ('source','destination') if (x:=r.get(role,{})).get('type')=='user-terminal' and x.get('id') is not None]
  terminal=str(terminals[0][1]['id']) if len(terminals)==1 else ''
  direction=('upload' if terminals[0][0]=='source' else 'download') if terminal else 'unknown'
  # This capture producer uses epoch microseconds; retain raw and refuse other scales.
  t=r.get('timestamp');start=r.get('start-time')
  ts=int(t)*1000 if isinstance(t,(int,float)) and 10**14<t<10**16 else None
  st=int(start)*1000 if isinstance(start,(int,float)) and 10**14<start<10**16 else None
  db.execute('INSERT INTO telemetry VALUES(?,?,?,?,?,?,?,?,?,?)',(frame,section,r['type'],str(r.get('comm-ses-id',r.get('id',''))),str(r.get('id','')) if r['type']=='stream' else '',st,ts,terminal,direction,json.dumps(r)))
 groups=collections.defaultdict(list)
 for r in db.execute("SELECT * FROM telemetry WHERE kind='stream' AND terminal!=''"):groups[(r['section'],r['comm'],r['stream'])].append(dict(r))
 refs=collections.defaultdict(list);root=None
 for ev,p in ET.iterparse(pdml,events=('start','end')):
  if root is None:root=p
  if ev!='end' or p.tag!='packet':continue
  d={f.get('name'):f.get('show','') for f in p.iter('field')};comment=object_json(d.get('frame.comment',''));frame=int(d.get('frame.number','0'))
  rr=db.execute('SELECT vessel_id FROM radius WHERE frame=?',(frame,)).fetchone()
  if rr and rr[0] and comment.get('com-ses-id'):
   refs[(int(d.get('frame.section_number','1'))-1,str(comment['com-ses-id']),str(comment.get('stream-id','')))].append((rr[0],frame))
  p.clear();root.clear()
 for key,records in groups.items():
  identities=refs.get(key,[]);vids={x[0] for x in identities};terminals={r['terminal'] for r in records};dirs={r['direction'] for r in records};starts={r['start_ns'] for r in records}
  if len(vids)!=1 or len(terminals)!=1 or len(dirs)!=1 or len(starts)!=1 or None in starts:continue
  db.execute('INSERT INTO satellite_mapping VALUES(NULL,?,?,?,?,?,?,?,?,?,?)',(next(iter(vids)),*key,next(iter(terminals)),next(iter(dirs)),next(iter(starts)),json.dumps([r['frame'] for r in records]),json.dumps([x[1] for x in identities]),'Exact section/session/stream annotation match. Terminal bearer associated with a probable NAS/site; individual subscriber is unknown.'))
 maps={(r['section'],r['comm'],r['stream']):dict(r) for r in db.execute('SELECT * FROM satellite_mapping')}
 for frame,section,typ,b,endian in blocks(path):
  if typ!=6:continue
  interface,th,tl,caplen,wirelen=struct.unpack(endian+'IIIII',b[:20]);pos=20+((caplen+3)//4)*4
  while pos+4<=len(b)-4:
   code,length=struct.unpack(endian+'HH',b[pos:pos+4]);pos+=4;value=b[pos:pos+length];pos+=((length+3)//4)*4
   if code==0:break
   if code!=1:continue
   r=object_json(value.decode('utf8',errors='replace'));key=(section,str(r.get('com-ses-id','')),str(r.get('stream-id','')))
   if key in maps:db.execute('INSERT OR IGNORE INTO satellite_packets VALUES(?,?,?,?)',(frame,maps[key]['id'],section,json.dumps(r)))
 db.commit()
