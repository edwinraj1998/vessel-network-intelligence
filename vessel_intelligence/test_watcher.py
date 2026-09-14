import unittest,tempfile,pathlib,struct,sqlite3,time,shutil,json
from unittest.mock import patch
from capture_input import validate,fingerprint
from watcher import registry,discover,tick,process

def pcap(path,payload=b''):
 # Raw IPv4, UDP DNS-like packet; no invented vessel information.
 packet=bytes.fromhex('4500001c00000000401100000a00000108080808')+struct.pack('!HHHH',1234,53,8,0)+payload
 path.write_bytes(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,101)+struct.pack('<IIII',1700000000,0,len(packet),len(packet))+packet)
def pcapng(path):
 def block(t,b):return struct.pack('<II',t,len(b)+12)+b+struct.pack('<I',len(b)+12)
 packet=bytes.fromhex('4500001c00000000401100000a00000108080808')+struct.pack('!HHHH',1234,53,8,0)
 path.write_bytes(block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))+block(1,struct.pack('<HHI',101,0,65535))+block(6,struct.pack('<IIIII',0,0,100,28,28)+packet))

class WatcherTests(unittest.TestCase):
 def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name);self.inbox=self.root/'in';self.inbox.mkdir();self.db=registry(self.root/'registry.sqlite')
 def tearDown(self):self.db.close();self.tmp.cleanup()
 def test_done_content_detection_and_unchanged_source(self):
  for name,make,fmt in [('one.done',pcap,'PCAP'),('two.done',pcapng,'PCAPNG'),('mislabeled.pcap',pcapng,'PCAPNG')]:
   path=self.inbox/name;make(path);before=path.read_bytes();info=validate(path);self.assertEqual(info['detected_format'],fmt);self.assertEqual(path.read_bytes(),before);self.assertEqual(info['filename'],name)
 def test_invalid_and_truncated_rejected(self):
  bad=self.inbox/'bad.done';bad.write_text('this is not a capture')
  with self.assertRaises(ValueError):validate(bad)
  pcap(bad);bad.write_bytes(bad.read_bytes()[:-3])
  with self.assertRaises(ValueError):validate(bad)
 def test_stability_restarts_when_file_changes(self):
  p=self.inbox/'a.done';pcap(p);discover(self.db,self.inbox,100)
  with patch('watcher.process') as worker:
   tick(self.db,self.inbox,self.root,30,now=120);worker.assert_not_called()
   p.write_bytes(p.read_bytes()+b'1234');tick(self.db,self.inbox,self.root,30,now=121);worker.assert_not_called()
   tick(self.db,self.inbox,self.root,30,now=152);worker.assert_called_once()
  self.assertEqual(self.db.execute("SELECT count(*) FROM files WHERE status='SUPERSEDED'").fetchone()[0],1)
 def test_registry_restart_and_duplicate_across_extensions(self):
  a=self.inbox/'a.pcap';pcap(a);b=self.inbox/'b.done';shutil.copyfile(a,b);discover(self.db,self.inbox,100)
  info=validate(a);self.db.execute("UPDATE files SET status='COMPLETED',sha256=? WHERE filename='a.pcap'",(info['sha256'],));self.db.commit()
  row=self.db.execute("SELECT * FROM files WHERE filename='b.done'").fetchone();process(self.db,row,self.root/'results');self.assertEqual(self.db.execute('SELECT status FROM files WHERE id=?',(row['id'],)).fetchone()[0],'DUPLICATE')
  self.db.close();self.db=registry(self.root/'registry.sqlite');discover(self.db,self.inbox,200);self.assertEqual(self.db.execute('SELECT count(*) FROM files').fetchone()[0],2)
 def test_failed_capture_does_not_block_next(self):
  (self.inbox/'bad.done').write_text('bad');pcap(self.inbox/'valid.done');discover(self.db,self.inbox,1)
  bad=self.db.execute("SELECT * FROM files WHERE filename='bad.done'").fetchone();process(self.db,bad,self.root/'results');self.assertEqual(self.db.execute('SELECT status FROM files WHERE id=?',(bad['id'],)).fetchone()[0],'FAILED')
  good=self.db.execute("SELECT * FROM files WHERE filename='valid.done'").fetchone();process(self.db,good,self.root/'results');self.assertEqual(self.db.execute('SELECT status FROM files WHERE id=?',(good['id'],)).fetchone()[0],'COMPLETED')

if __name__=='__main__':unittest.main(verbosity=2)
