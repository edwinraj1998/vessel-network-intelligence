"""Read original captures by content, including .done. Never rename source evidence."""
import pathlib,subprocess,hashlib,json
VERSION='2.1'
SUPPORTED_CAPTURE_EXTENSIONS={'.pcap','.pcapng','.done'}
def fingerprint(path):
 s=pathlib.Path(path).stat();return (s.st_size,s.st_mtime_ns)
def validate(path):
 from core import executable
 path=pathlib.Path(path).resolve()
 if path.suffix.lower() not in SUPPORTED_CAPTURE_EXTENSIONS:raise ValueError('Supported extensions: .pcap, .pcapng, .done')
 before=fingerprint(path)
 r=subprocess.run([executable('tshark'),'-n','-r',str(path),'-c','1','-T','fields','-e','frame.number'],capture_output=True,text=True,encoding='utf8',errors='replace',timeout=120)
 if r.returncode:raise ValueError('TShark cannot parse capture: '+r.stderr[-2000:])
 # Full capinfos traversal also detects truncated records after a readable first packet.
 r=subprocess.run([executable('capinfos'),'-M','-t','-E','-c','-a','-e','-s',str(path)],capture_output=True,text=True,encoding='utf8',errors='replace')
 if r.returncode:raise ValueError('Capture is incomplete or invalid: '+r.stderr[-2000:])
 if fingerprint(path)!=before:raise BlockingIOError('Source changed during validation')
 fields={line.split(':',1)[0].strip():line.split(':',1)[1].strip() for line in r.stdout.splitlines() if ':' in line}
 with path.open('rb') as f:magic=f.read(4)
 fmt='PCAPNG' if magic==b'\x0a\x0d\x0d\x0a' else 'PCAP' if magic in (b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d') else fields.get('File type','Other Wireshark format')
 if fmt not in ('PCAP','PCAPNG'):raise ValueError('Input must contain PCAP or PCAPNG records; arbitrary data is not a capture')
 h=hashlib.sha256()
 with path.open('rb') as f:
  while chunk:=f.read(8*1024*1024):h.update(chunk)
 if fingerprint(path)!=before:raise BlockingIOError('Source changed during hashing')
 return dict(filename=path.name,extension=path.suffix.lower(),detected_format=fmt,encapsulation=fields.get('File encapsulation','Unknown'),size=before[0],modified_time_ns=before[1],sha256=h.hexdigest(),validation='tshark first record + full capinfos traversal',capinfos_raw=r.stdout)
