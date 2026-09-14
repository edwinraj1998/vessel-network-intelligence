import unittest,tempfile,pathlib,sqlite3,xml.etree.ElementTree as ET,struct,json,ipaddress,hashlib
from reconstruction import Writer,SCHEMA,packet_artifacts,smpp_message,media_type,build,payload_for
from core import dbopen,putmeta,SCHEMA as CORE_SCHEMA

def smpp(text=b'Hello',coding=0):
 body=b'\0'+b'\x01\x01'+b'12345\0'+b'\x01\x01'+b'67890\0'+b'\x00\x00\x00'+b'\0\0'+bytes([0,0,coding,0,len(text)])+text
 return struct.pack('!IIII',len(body)+16,4,0,1)+body

def pdml(body,frames=(1,),mime='image/png'):
 p=ET.Element('packet');g=ET.SubElement(p,'proto',name='frame')
 for n,v in [('frame.number',str(frames[-1])),('frame.time_epoch','1700000000'),('frame.protocols','ip:tcp:http'),('ip.src','1.2.3.4'),('ip.dst','5.6.7.8')]:ET.SubElement(g,'field',name=n,show=v)
 for f in frames:ET.SubElement(g,'field',name='tcp.segment',show=str(f))
 h=ET.SubElement(p,'proto',name='http');ET.SubElement(h,'field',name='http.content_type',show=mime);ET.SubElement(h,'field',name='http.content_length',show=str(len(body)));ET.SubElement(h,'field',name='http.file_data',size=str(len(body)),value=body.hex());return p

class RecoveryTests(unittest.TestCase):
 def test_smtp_fragment_reassembly_rejects_gaps_and_conflicts(self):
  raw=b'From: a@example.test\r\nTo: b@example.test\r\nSubject: Test\r\n\r\nMessage body'
  p=ET.Element('packet');imf=ET.SubElement(p,'proto',name='imf',pos='0',size=str(len(raw)))
  ET.SubElement(p,'field',name='smtp.data.reassembled.length',show=str(len(raw)))
  ET.SubElement(p,'field',name='smtp.data.fragment',pos='0',value=raw[:30].hex())
  last=ET.SubElement(p,'field',name='smtp.data.fragment',pos='30',value=raw[30:].hex())
  self.assertEqual(payload_for(p,imf),raw)
  last.set('pos','31');self.assertIsNone(payload_for(p,imf))
  last.set('pos','29');self.assertIsNone(payload_for(p,imf))
 def test_sms_strict_framing_and_unicode(self):
  self.assertEqual(smpp_message(smpp())['text'],'Hello');self.assertEqual(smpp_message(smpp('Hi €'.encode('utf-16-be'),8))['text'],'Hi €')
  self.assertIsNone(smpp_message(smpp()[:-1]));self.assertIsNone(smpp_message(b'HTTP/1.1 200 OK\r\n'));self.assertIsNone(smpp_message(b'\0'*50))
 def test_media_signature_beats_claimed_type(self):
  self.assertEqual(media_type(b'\x89PNG\r\n\x1a\n','text/html'),('Image','image/png'));self.assertEqual(media_type(b'<script>bad()</script>','application/octet-stream')[0],'HTTP')
 def test_cross_session_bytes_are_not_assigned(self):
  with tempfile.TemporaryDirectory() as td:
   d=sqlite3.connect(':memory:');d.row_factory=sqlite3.Row;d.executescript(SCHEMA+'CREATE TABLE links(frame INTEGER,vessel_id INTEGER,session_id INTEGER);');d.executemany('INSERT INTO links VALUES(?,?,?)',[(1,1,10),(2,1,11)])
   w=Writer(d,pathlib.Path(td));packet_artifacts(pdml(b'\x89PNG\r\n\x1a\n',[1,2]),w);self.assertEqual(d.execute('SELECT count(*) FROM artifact_links').fetchone()[0],0)
   d.execute('UPDATE links SET session_id=10');packet_artifacts(pdml(b'\x89PNG\r\n\x1a\n',[1,2]),w);self.assertEqual(d.execute('SELECT count(*) FROM artifact_links').fetchone()[0],1);d.close()
 def test_port_is_not_sms_and_active_text_preserved_as_bytes(self):
  with tempfile.TemporaryDirectory() as td:
   d=sqlite3.connect(':memory:');d.row_factory=sqlite3.Row;d.executescript(SCHEMA+'CREATE TABLE links(frame INTEGER,vessel_id INTEGER,session_id INTEGER);');w=Writer(d,pathlib.Path(td));p=pdml(b'<script>alert(1)</script>',mime='text/html');ET.SubElement(p,'field',name='tcp.srcport',show='5002');packet_artifacts(p,w)
   self.assertEqual(d.execute("SELECT count(*) FROM artifacts WHERE kind='SMS'").fetchone()[0],0);self.assertTrue(d.execute("SELECT path FROM artifacts WHERE kind='HTTP'").fetchone()[0].endswith('.bin'));d.close()
 def test_real_capture_http_and_custom_port_sms(self):
  with tempfile.TemporaryDirectory() as td:
   root=pathlib.Path(td);source=root/'test.done';image=b'\x89PNG\r\n\x1a\n'+b'test-only-payload';body=b'HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: '+str(len(image)).encode()+b'\r\n\r\n'+image
   def tcp(data,sp,dp):
    t=struct.pack('!HHIIBBHHH',sp,dp,1,1,80,24,65535,0,0)+data
    return struct.pack('!BBHHHBBH4s4s',69,0,len(t)+20,1,0,64,6,0,ipaddress.ip_address('1.2.3.4').packed,ipaddress.ip_address('5.6.7.8').packed)+t
   packets=[tcp(body,80,23456),tcp(smpp(),5002,33333)]
   with source.open('wb') as f:
    f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,101))
    for i,b in enumerate(packets):f.write(struct.pack('<IIII',1700000000+i,0,len(b),len(b))+b)
   dbpath=root/'analysis.sqlite';d=dbopen(dbpath);d.executescript(CORE_SCHEMA);putmeta(d,'pcap',str(source));putmeta(d,'sha256',hashlib.sha256(source.read_bytes()).hexdigest());d.commit();d.close();build(dbpath)
   d=sqlite3.connect(dbpath);kinds=[r[0] for r in d.execute('SELECT kind FROM artifacts')];self.assertIn('Image',kinds);self.assertIn('SMS',kinds);self.assertEqual(d.execute("SELECT preview FROM artifacts WHERE kind='SMS'").fetchone()[0],'Hello');d.close()

if __name__=='__main__':unittest.main()
