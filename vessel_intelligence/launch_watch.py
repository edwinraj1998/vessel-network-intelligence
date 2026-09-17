"""Select a folder, start the persistent watcher and open Capture Files."""
import argparse,json,pathlib,subprocess,sys,time,webbrowser,os,urllib.request
ROOT=pathlib.Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--folder');p.add_argument('--out');p.add_argument('--port',type=int,default=8768);a=p.parse_args()
folder=a.folder
if not folder:
 from tkinter import Tk,filedialog
 window=Tk();window.withdraw();folder=filedialog.askdirectory(title='Select folder receiving .pcap, .pcapng and .done captures');window.destroy()
if not folder:sys.exit('No folder selected.')
out=pathlib.Path(a.out).resolve() if a.out else ROOT.parent/'watch_data';out.mkdir(parents=True,exist_ok=True)
from watcher import registry
db=registry(out/'registry.sqlite');db.close()
recovery=subprocess.Popen([sys.executable,str(ROOT/'reconstruction_worker.py'),'--registry',str(out/'registry.sqlite')])
intelligence=subprocess.Popen([sys.executable,str(ROOT/'intelligence_worker.py'),'--registry',str(out/'registry.sqlite')])
watch=subprocess.Popen([sys.executable,str(ROOT/'watcher.py'),folder,'--out',str(out)])
server=None;existing=False
try:
 with urllib.request.urlopen(f'http://127.0.0.1:{a.port}/api/captures',timeout=1) as response:
  existing=pathlib.Path(json.load(response).get('registry','')).resolve()==(out/'registry.sqlite').resolve()
except (OSError,ValueError):pass
if not existing:server=subprocess.Popen([sys.executable,str(ROOT/'server.py'),'--registry',str(out/'registry.sqlite'),'--port',str(a.port)])
try:
 time.sleep(1)
 if watch.poll() is not None or (server and server.poll() is not None):raise RuntimeError('Watcher or server failed to start. Check the console; another instance may be running.')
 webbrowser.open(f'http://127.0.0.1:{a.port}/captures');print('Keep this console open. Ctrl+C stops watching.');watch.wait()
except KeyboardInterrupt:pass
finally:
 for child in (watch,server,recovery,intelligence):
  if child and child.poll() is None:
   if os.name=='nt':subprocess.run(['taskkill','/PID',str(child.pid),'/T','/F'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   else:child.terminate()
   child.wait()
