"""Persistent sequential queue for original .pcap/.pcapng/.done evidence."""
import argparse,collections,hashlib,json,pathlib,sqlite3,subprocess,sys,time,os
from capture_input import SUPPORTED_CAPTURE_EXTENSIONS,validate,fingerprint,VERSION
ROOT=pathlib.Path(__file__).resolve().parent
SCHEMA='''
CREATE TABLE IF NOT EXISTS files(id INTEGER PRIMARY KEY,path TEXT,filename TEXT,extension TEXT,size INTEGER,modified_time INTEGER,stable_since REAL,status TEXT,detected_format TEXT,encapsulation TEXT,sha256 TEXT,capture_start INTEGER,capture_end INTEGER,packet_count INTEGER,processing_started REAL,processing_completed REAL,parser_version TEXT,error TEXT,dbpath TEXT,progress TEXT,duplicate_of INTEGER, UNIQUE(path,size,modified_time));
CREATE TABLE IF NOT EXISTS profile_observations(profile_key TEXT,file_id INTEGER,vessel_id INTEGER,name TEXT,nas TEXT,confidence TEXT,packets INTEGER,bytes INTEGER,first_seen INTEGER,last_seen INTEGER,evidence TEXT, PRIMARY KEY(file_id,vessel_id));
CREATE TABLE IF NOT EXISTS session_observations(session_key TEXT,file_id INTEGER,session_id INTEGER,profile_key TEXT,start INTEGER,end INTEGER,ips TEXT,frames TEXT, PRIMARY KEY(file_id,session_id));
'''
def registry(path):
 d=sqlite3.connect(path,timeout=30);d.row_factory=sqlite3.Row;d.execute('PRAGMA journal_mode=WAL');d.executescript(SCHEMA);return d
def update(d,i,**kw):
 d.execute('UPDATE files SET '+','.join(k+'=?' for k in kw)+' WHERE id=?',list(kw.values())+[i]);d.commit()
def discover(d,folder,now,recursive=False):
 paths=pathlib.Path(folder).rglob('*') if recursive else pathlib.Path(folder).iterdir()
 for p in paths:
  if p.suffix.lower() not in SUPPORTED_CAPTURE_EXTENSIONS or not p.is_file():continue
  try:size,mtime=fingerprint(p)
  except OSError:continue
  path=str(p.resolve());d.execute("UPDATE files SET status='SUPERSEDED',error='File changed before processing' WHERE path=? AND status IN ('WAITING_FOR_FILE','FAILED') AND (size!=? OR modified_time!=?)",(path,size,mtime))
  d.execute("INSERT OR IGNORE INTO files(path,filename,extension,size,modified_time,stable_since,status,parser_version) VALUES(?,?,?,?,?,?,'WAITING_FOR_FILE',?)",(path,p.name,p.suffix.lower(),size,mtime,now,VERSION))
 d.commit()
def history(d,file_id,dbpath):
 a=sqlite3.connect(dbpath);a.row_factory=sqlite3.Row
 for v in a.execute('SELECT * FROM vessels'):
  # Exact NAS/site evidence is a candidate history group, never an IP-only identity.
  namespace=sorted({r[0] for r in a.execute('SELECT context FROM radius WHERE vessel_id=?',(v['id'],))})
  key=hashlib.sha256(json.dumps([v['name'],v['nas'],namespace]).encode()).hexdigest()[:24]
  totals=a.execute('SELECT coalesce(sum(packets),0),coalesce(sum(bytes),0) FROM flows WHERE vessel_id=?',(v['id'],)).fetchone()
  times=a.execute('SELECT min(t),max(t) FROM radius WHERE vessel_id=?',(v['id'],)).fetchone()
  d.execute('INSERT OR REPLACE INTO profile_observations VALUES(?,?,?,?,?,?,?,?,?,?,?)',(key,file_id,v['id'],v['name'],v['nas'],'Medium — matching NAS/site and namespace; vessel unverified',*totals,*times,v['evidence']))
  for s in a.execute('SELECT * FROM sessions WHERE vessel_id=?',(v['id'],)):
   sk=hashlib.sha256(json.dumps([key,s['acct_id'],s['username'],s['calling_station']]).encode()).hexdigest()[:24]
   ips=[dict(r) for r in a.execute('SELECT ip,start,end,frames FROM assignments WHERE session_id=?',(s['id'],))]
   d.execute('INSERT OR REPLACE INTO session_observations VALUES(?,?,?,?,?,?,?,?)',(sk,file_id,s['id'],key,s['start'],s['end'],json.dumps(ips),s['frames']))
 a.close();d.commit()
def process(d,row,out):
 i=row['id'];path=pathlib.Path(row['path']);attempt=pathlib.Path(out)/f'capture_{i}_{time.time_ns()}'
 update(d,i,status='VALIDATING',processing_started=time.time(),error=None)
 try:
  if fingerprint(path)!=(row['size'],row['modified_time']):raise BlockingIOError('Source changed before validation')
  info=validate(path)
  duplicate=d.execute("SELECT id FROM files WHERE sha256=? AND status='COMPLETED' AND parser_version=? LIMIT 1",(info['sha256'],VERSION)).fetchone()
  update(d,i,detected_format=info['detected_format'],encapsulation=info['encapsulation'],sha256=info['sha256'])
  if duplicate:update(d,i,status='DUPLICATE',duplicate_of=duplicate[0],processing_completed=time.time());return
  update(d,i,status='QUEUED');attempt.mkdir(parents=True);update(d,i,status='PROCESSING',dbpath=str(attempt/'analysis.sqlite'))
  with (attempt/'pipeline.log').open('w',encoding='utf8') as log:
   p=subprocess.Popen([sys.executable,str(ROOT/'core.py'),str(path),'--out',str(attempt)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding='utf8',errors='replace')
   try:
    for line in p.stdout:
     log.write(line);log.flush()
     if line.startswith('{'):update(d,i,progress=line.strip())
    rc=p.wait()
   finally:
    if p.poll() is None:p.terminate();p.wait()
    p.stdout.close()
  if fingerprint(path)!=(row['size'],row['modified_time']):raise BlockingIOError('Source changed during analysis; incomplete results excluded')
  if rc:raise RuntimeError('Analysis failed; see '+str(attempt/'pipeline.log'))
  a=sqlite3.connect(attempt/'analysis.sqlite');m={k:json.loads(v) for k,v in a.execute('SELECT key,value FROM meta')};a.close()
  if m.get('status')!='complete':raise RuntimeError('Analysis did not complete')
  history(d,i,attempt/'analysis.sqlite')
  update(d,i,status='COMPLETED',capture_start=m.get('capture_start_ns'),capture_end=m.get('capture_end_ns'),packet_count=m.get('capture_stats',{}).get('packets'),processing_completed=time.time())
 except BlockingIOError as e:update(d,i,status='WAITING_FOR_FILE',stable_since=time.time(),error=str(e))
 except Exception as e:update(d,i,status='FAILED',error=str(e),processing_completed=time.time())
def tick(d,folder,out,stable_seconds=30,recursive=False,now=None):
 now=time.time() if now is None else now;discover(d,folder,now,recursive)
 row=d.execute("SELECT * FROM files WHERE status='WAITING_FOR_FILE' AND stable_since<=? ORDER BY id LIMIT 1",(now-stable_seconds,)).fetchone()
 if row:process(d,row,out)
 return row is not None
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder');p.add_argument('--out',required=True);p.add_argument('--stable-seconds',type=float,default=30);p.add_argument('--poll-seconds',type=float,default=5);p.add_argument('--recursive',action='store_true');p.add_argument('--once',action='store_true');a=p.parse_args()
 if not pathlib.Path(a.folder).is_dir():p.error('Monitor folder must exist')
 if a.stable_seconds<1 or a.poll_seconds<.1:p.error('Use a stability interval >=1 second and polling >=0.1 second')
 out=pathlib.Path(a.out).resolve();out.mkdir(parents=True,exist_ok=True)
 # OS advisory lock is automatically released on crash. Prevent competing watcher processes.
 lock=(out/'watcher.lock').open('a+b');lock.seek(0);lock.write(b'0');lock.flush();lock.seek(0)
 try:
  if os.name=='nt':
   import msvcrt;msvcrt.locking(lock.fileno(),msvcrt.LK_NBLCK,1)
  else:
   import fcntl;fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 except OSError:raise SystemExit('A watcher already owns this output registry')
 d=registry(out/'registry.sqlite')
 d.execute("UPDATE files SET status='WAITING_FOR_FILE',stable_since=?,error='Recovered interrupted work; retrying' WHERE status IN ('VALIDATING','QUEUED','PROCESSING')",(time.time(),));d.commit()
 print('Watching',a.folder,'Registry:',out/'registry.sqlite',flush=True)
 try:
  while True:
   worked=tick(d,a.folder,out,a.stable_seconds,a.recursive)
   if a.once:break
   if not worked:time.sleep(a.poll_seconds)
 except KeyboardInterrupt:pass
 finally:d.close();lock.close()
if __name__=='__main__':main()
