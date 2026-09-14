"""Read-only localhost dashboard with pagination, evidence and streaming exports."""
import argparse,csv,io,json,pathlib,sqlite3,struct,urllib.parse,hashlib
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from core import ROOT,dumps
from report import catalog,profile,table,evidence,query

def isolated_capture(path,selected):
 """Stream original packet blocks without editing payloads. Selected source frame numbers are ordered."""
 selected=iter(selected);target=next(selected,None);frame=0
 with open(path,'rb') as f:
  magic=f.read(4);f.seek(0)
  if magic==b'\x0a\x0d\x0d\x0a':
   endian='<'
   while header:=f.read(8):
    if len(header)!=8:raise ValueError('Truncated PCAPNG block header')
    extra=b''
    if header[:4]==magic:
     extra=f.read(4)
     if extra not in (b'\x4d\x3c\x2b\x1a',b'\x1a\x2b\x3c\x4d'):raise ValueError('Invalid PCAPNG byte order')
     endian='<' if extra==b'\x4d\x3c\x2b\x1a' else '>'
    typ,length=struct.unpack(endian+'II',header)
    if length<12 or length%4 or length>64*1024*1024:raise ValueError('Invalid/oversized PCAPNG block')
    rest=f.read(length-8-len(extra));block=header+extra+rest
    if len(block)!=length or struct.unpack(endian+'I',block[-4:])[0]!=length:raise ValueError('Corrupt PCAPNG block')
    # Wireshark exposes custom blocks as frame records too (519 in the supplied capture).
    # Ignoring these shifts every subsequent frame selection and exports wrong packets.
    if typ in (2,3,6,9,0x00000bad,0x40000bad):
     frame+=1
     while target is not None and target<frame:target=next(selected,None)
     if target==frame:yield block;target=next(selected,None)
    elif typ in (0x0a0d0d0a,1):
     # Keep only section and interface descriptions, not unrelated comments, secrets or name records.
     if typ==0x0a0d0d0a:block=block[:16]+b'\xff'*8+block[24:]
     yield block
    elif typ not in (4,5,10):raise ValueError(f'Unsupported PCAPNG block type {typ:#x}; refusing uncertain frame indexing')
  else:
   modes={b'\xd4\xc3\xb2\xa1':'<',b'\xa1\xb2\xc3\xd4':'>',b'\x4d\x3c\xb2\xa1':'<',b'\xa1\xb2\x3c\x4d':'>'}
   if magic not in modes:raise ValueError('Isolation export supports PCAP and PCAPNG')
   endian=modes[magic];yield f.read(24)
   while header:=f.read(16):
    if len(header)!=16:raise ValueError('Truncated PCAP record')
    size=struct.unpack(endian+'IIII',header)[2]
    if size>64*1024*1024:raise ValueError('Oversized packet')
    body=f.read(size)
    if len(body)!=size:raise ValueError('Truncated PCAP packet')
    frame+=1
    while target is not None and target<frame:target=next(selected,None)
    if target==frame:yield header+body;target=next(selected,None)

class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  # Bind loopback, block cross-origin embedding/requests and DNS rebinding hostnames.
  if self.headers.get('Host','').split(':')[0] not in ('127.0.0.1','localhost'):
   self.send_error(403);return
  origin=self.headers.get('Origin')
  if origin and origin not in (f'http://127.0.0.1:{self.server.server_port}',f'http://localhost:{self.server.server_port}'):
   self.send_error(403);return
  url=urllib.parse.urlsplit(self.path);q={k:v[0] for k,v in urllib.parse.parse_qs(url.query).items()}
  dbpath=self.server.dbpath
  regpath=getattr(self.server,'registry',None)
  if regpath:
   reg=sqlite3.connect(regpath);reg.row_factory=sqlite3.Row
   try:
    if url.path=='/captures' or (url.path=='/' and not q.get('capture')):
     self.send_bytes((ROOT/'capture_files.html').read_bytes(),'text/html; charset=utf-8');return
    if url.path=='/api/captures':
     conditions=[];args=[];filter=q.get('filter','All')
     if filter in ('PCAP','PCAPNG','DONE'):conditions.append('extension=?');args.append('.'+filter.lower())
     elif filter=='Processing':conditions.append("status IN ('WAITING_FOR_FILE','VALIDATING','QUEUED','PROCESSING')")
     elif filter in ('Completed','Failed'):conditions.append('status=?');args.append(filter.upper())
     if q.get('q'):conditions.append('(filename LIKE ? OR detected_format LIKE ? OR status LIKE ?)');args += ['%'+q['q']+'%']*3
     where=' WHERE '+' AND '.join(conditions) if conditions else ''
     files=[dict(r) for r in reg.execute('SELECT * FROM files'+where+' ORDER BY id DESC LIMIT 100 OFFSET ?',args+[max(0,int(q.get('offset','0')))])]
     self.send_json({'registry':str(regpath),'files':files,'counts':[dict(r) for r in reg.execute('SELECT status,count(*) n FROM files GROUP BY status')]});return
    if url.path=='/api/history':
     if q.get('key'):
      self.send_json({'observations':[dict(r) for r in reg.execute("SELECT p.*,f.filename FROM profile_observations p JOIN files f ON p.file_id=f.id WHERE p.profile_key=? AND f.status='COMPLETED' ORDER BY p.first_seen",(q['key'],))],'sessions':[dict(r) for r in reg.execute("SELECT s.*,f.filename FROM session_observations s JOIN files f ON f.id=s.file_id WHERE s.profile_key=? AND f.status='COMPLETED' ORDER BY s.start",(q['key'],))]})
     else:self.send_json([dict(r) for r in reg.execute("SELECT profile_key,name,nas,confidence,count(*) captures,sum(packets) packets,sum(bytes) bytes FROM profile_observations p JOIN files f ON p.file_id=f.id WHERE f.status='COMPLETED' GROUP BY profile_key ORDER BY name")])
     return
    item=reg.execute("SELECT dbpath FROM files WHERE id=? AND status='COMPLETED'",(int(q.get('capture','0')),)).fetchone()
    if not item:self.send_error(404,'Select a completed capture');return
    dbpath=pathlib.Path(item[0])
   except (ValueError,sqlite3.Error) as exc:self.send_error(400,str(exc));return
   finally:reg.close()
  db=sqlite3.connect(dbpath.as_uri()+'?mode=ro',uri=True);db.row_factory=sqlite3.Row
  try:
   vid=int(q.get('vessel','0'));kind=q.get('kind','sessions');limit=min(1000,max(1,int(q.get('limit','200'))));offset=max(0,int(q.get('offset','0')))
   if url.path=='/':self.send_bytes((ROOT/'dashboard.html').read_bytes(),'text/html; charset=utf-8')
   elif url.path=='/api/catalog':self.send_json(catalog(db))
   elif url.path=='/api/reconstruction':
    from reconstruction_api import listing
    self.send_json(listing(db,vid,q))
   elif url.path=='/api/artifact':
    from reconstruction_api import detail
    self.send_json(detail(db,int(q.get('id','0')),vid,q)[0])
   elif url.path=='/artifact':
    from reconstruction_api import serve_file
    serve_file(self,db,dbpath,int(q.get('id','0')),vid,q)
   elif url.path=='/api/profile':self.send_json(profile(db,vid))
   elif url.path=='/api/table':self.send_json(table(db,kind,vid,q,limit,offset))
   elif url.path=='/api/evidence':self.send_json(evidence(db,vid,int(q.get('frame','0')),int(q.get('flow','0')),int(q.get('session','0')),offset))
   elif url.path=='/api/search':
    term='%'+q.get('q','')+'%';found=[]
    for source,sql in [('identity',"SELECT id vessel_id,name FROM vessels WHERE name LIKE ? OR username LIKE ? OR calling_station LIKE ?"),('identities',"SELECT DISTINCT vessel_id,(SELECT name FROM vessels WHERE id=vessel_id) name FROM radius WHERE vessel_id IS NOT NULL AND (username LIKE ? OR calling_station LIKE ? OR acct_id LIKE ? OR nas LIKE ? OR ips LIKE ?)"),('traffic',"SELECT DISTINCT l.vessel_id,v.name FROM packets p JOIN links l ON l.frame=p.frame JOIN vessels v ON v.id=l.vessel_id JOIN flows f ON f.id=l.flow_id WHERE p.src LIKE ? OR p.dst LIKE ? OR p.sport LIKE ? OR p.dport LIKE ? OR p.protocols LIKE ? OR f.domain LIKE ? OR f.service LIKE ?")]:
     for r in db.execute(sql+' LIMIT 100',[term]*sql.count('?')):found.append(dict(r,source=source))
    self.send_json(found)
   elif url.path=='/export/csv':
    sql,args=query(db,kind,vid,q);cur=db.execute(sql,args);self.headers_out('text/csv; charset=utf-8',f'vessel-{vid}-{kind}.csv');buf=io.StringIO(newline='');writer=csv.writer(buf)
    def emit(vals):
     writer.writerow([("'"+str(v)) if isinstance(v,str) and v.lstrip().startswith(('=','+','-','@','\t','\r')) else v for v in vals]);self.wfile.write(buf.getvalue().encode('utf8'));buf.seek(0);buf.truncate(0)
    filename=json.loads(db.execute("SELECT value FROM meta WHERE key='filename'").fetchone()[0])
    emit(['source_filename']+[c[0] for c in cur.description])
    for r in cur:emit([filename]+list(r))
   elif url.path=='/export/html':self.send_bytes((dbpath.parent/'report.html').read_bytes(),'text/html; charset=utf-8','vessel-report.html')
   elif url.path=='/export/telemetry':
    result={'source':catalog(db)['meta'],'note':'JSON sidecar preserves original custom telemetry evidence; noncopy custom blocks are not inserted into isolated captures.','mappings':[]}
    if db.execute("SELECT 1 FROM sqlite_master WHERE name='satellite_mapping'").fetchone():
     for r in db.execute('SELECT id FROM satellite_mapping WHERE vessel_id=?',(vid,)):result['mappings'].append(evidence(db,vid,session=-r[0]))
    self.send_bytes(dumps(result).encode('utf8'),'application/json; charset=utf-8',f'vessel-{vid}-satellite-evidence.json')
   elif url.path=='/export/pcap':
    source=pathlib.Path(json.loads(db.execute("SELECT value FROM meta WHERE key='pcap'").fetchone()[0]));selected=(r[0] for r in db.execute('SELECT frame FROM links WHERE vessel_id=? UNION SELECT frame FROM radius WHERE vessel_id=? ORDER BY frame',(vid,vid)))
    digest=hashlib.sha256()
    with source.open('rb') as fp:
     while chunk:=fp.read(8*1024*1024):digest.update(chunk)
    if digest.hexdigest()!=json.loads(db.execute("SELECT value FROM meta WHERE key='sha256'").fetchone()[0]):raise ValueError('Source content changed since analysis; refusing to export mismatched evidence')
    self.headers_out('application/octet-stream',f'vessel-{vid}-evidence{source.suffix}')
    for chunk in isolated_capture(source,selected):self.wfile.write(chunk)
   else:self.send_error(404)
  except (BrokenPipeError,ConnectionResetError):pass
  except Exception as exc:self.send_error(400,str(exc))
  finally:db.close()
 def headers_out(self,mime,name=None):
  self.send_response(200);self.send_header('Content-Type',mime);self.send_header('X-Content-Type-Options','nosniff');self.send_header('Cache-Control','no-store');self.send_header('Referrer-Policy','no-referrer');self.send_header('X-Frame-Options','DENY')
  if name:self.send_header('Content-Disposition',f'attachment; filename="{name}"')
  self.end_headers()
 def send_bytes(self,b,mime,name=None):self.headers_out(mime,name);self.wfile.write(b)
 def send_json(self,obj):self.send_bytes(dumps(obj).encode('utf8'),'application/json; charset=utf-8')

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('database',nargs='?',default='');p.add_argument('--registry');p.add_argument('--port',type=int,default=8765);a=p.parse_args();srv=ThreadingHTTPServer(('127.0.0.1',a.port),Handler);srv.dbpath=pathlib.Path(a.database).resolve();srv.registry=pathlib.Path(a.registry).resolve() if a.registry else None;print(f'Open http://127.0.0.1:{a.port} — Ctrl+C to stop',flush=True)
 try:srv.serve_forever()
 except KeyboardInterrupt:pass
