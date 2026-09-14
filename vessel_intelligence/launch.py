"""Launch a saved analysis, or select a new local capture with --analyze."""
import argparse,datetime,pathlib,subprocess,sys,webbrowser,time,urllib.request,json,sqlite3
ROOT=pathlib.Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--database');p.add_argument('--pcap');p.add_argument('--analyze',action='store_true');p.add_argument('--port',type=int,default=8769);a=p.parse_args()
database=pathlib.Path(a.database) if a.database else ROOT.parent/'integrated_capture'/'analysis.sqlite'
if a.analyze or a.pcap:
 capture=a.pcap
 if not capture:
  from tkinter import Tk,filedialog
  root=Tk();root.withdraw();capture=filedialog.askopenfilename(title='Select PCAP for offline vessel analysis',filetypes=[('Packet captures','*.pcap *.pcapng *.done'),('All files','*.*')]);root.destroy()
 if not capture:sys.exit('No capture selected.')
 out=ROOT.parent/('analysis_'+datetime.datetime.now().strftime('%Y%m%d_%H%M%S'))
 subprocess.run([sys.executable,str(ROOT/'core.py'),capture,'--out',str(out)],check=True);database=out/'analysis.sqlite'
if not database.is_file():sys.exit('No analysis database found. Run launch.py --analyze to select a capture.')
try:
 with urllib.request.urlopen(f'http://127.0.0.1:{a.port}/api/catalog',timeout=1) as response:running=json.load(response)
 with sqlite3.connect(database) as db:expected=json.loads(db.execute("SELECT value FROM meta WHERE key='sha256'").fetchone()[0])
 if running.get('meta',{}).get('sha256')==expected and running.get('meta',{}).get('parser_version')=='2.0':
  webbrowser.open(f'http://127.0.0.1:{a.port}');sys.exit(0)
except (OSError,ValueError,TypeError,sqlite3.Error):pass
server=subprocess.Popen([sys.executable,str(ROOT/'server.py'),str(database),'--port',str(a.port)])
try:
 time.sleep(.7)
 if server.poll() is not None:sys.exit('Server failed to start. Try another --port.')
 webbrowser.open(f'http://127.0.0.1:{a.port}');server.wait()
except KeyboardInterrupt:server.terminate();server.wait()
