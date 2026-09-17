import pathlib,sys,struct,sqlite3,tempfile,subprocess,importlib
from core import executable
print("Satellite Intelligence 3.0 offline installation check")
assert sys.version_info[:2]==(3,12), "Python 3.12 required for this wheel bundle"
assert struct.calcsize("P")==8,"64-bit Python required"
print("Python:",sys.version.split()[0],"SQLite:",sqlite3.sqlite_version)
for name in ("tkinter","cryptography","cffi"):
 module=importlib.import_module(name);print(name,getattr(module,"__version__","available"))
for name in ("tshark","capinfos","editcap"):
 p=executable(name);result=subprocess.run([p,"--version"],capture_output=True,text=True,check=True);print(result.stdout.splitlines()[0])
root=pathlib.Path(__file__).resolve().parent.parent
with tempfile.TemporaryFile(dir=root) as f:f.write(b"write check")
print("PASS: dependencies and writable installation folder. Run Validation Tests for packet analysis checks.")
