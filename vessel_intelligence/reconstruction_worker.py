"""Upgrade previously completed registry entries with content reconstruction."""
import argparse,json,pathlib,sqlite3,subprocess,sys,time,os
ROOT=pathlib.Path(__file__).resolve().parent

def main():
 p=argparse.ArgumentParser();p.add_argument('--registry',required=True);p.add_argument('--once',action='store_true');a=p.parse_args();reg=pathlib.Path(a.registry).resolve()
 lock=reg.with_name('reconstruction.lock').open('a+b');lock.seek(0);lock.write(b'0');lock.flush();lock.seek(0)
 try:
  if os.name=='nt':
   import msvcrt;msvcrt.locking(lock.fileno(),msvcrt.LK_NBLCK,1)
  else:
   import fcntl;fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 except OSError:return
 try:
  while True:
   with sqlite3.connect(reg) as d:paths=[r[0] for r in d.execute("SELECT dbpath FROM files WHERE status='COMPLETED' ORDER BY id")]
   for path in paths:
    if not path or not pathlib.Path(path).exists():continue
    with sqlite3.connect(path,timeout=30) as d:
     m={k:json.loads(v) for k,v in d.execute("SELECT key,value FROM meta WHERE key LIKE 'reconstruction_%'")}
     if m.get('reconstruction_version') or m.get('reconstruction_status')=='Processing' or m.get('reconstruction_worker_attempt'):continue
     d.execute("INSERT OR REPLACE INTO meta VALUES('reconstruction_worker_attempt','true')");d.commit()
    with pathlib.Path(path).with_name('reconstruction-worker.log').open('w',encoding='utf8') as log:
     subprocess.run([sys.executable,str(ROOT/'reconstruction.py'),path],stdout=log,stderr=subprocess.STDOUT)
   if a.once:break
   time.sleep(10)
 except KeyboardInterrupt:pass
 finally:lock.close()
if __name__=='__main__':main()
