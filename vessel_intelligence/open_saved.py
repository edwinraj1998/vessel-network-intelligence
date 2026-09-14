import pathlib,subprocess,sys
from tkinter import Tk,filedialog
root=Tk();root.withdraw();path=filedialog.askopenfilename(title="Select analysis.sqlite",filetypes=[("SQLite analysis","*.sqlite")]);root.destroy()
if path:subprocess.run([sys.executable,str(pathlib.Path(__file__).with_name("launch.py")),"--database",path],check=True)
