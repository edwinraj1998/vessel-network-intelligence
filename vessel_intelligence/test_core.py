"""Deterministic adversarial tests. No Internet, no packet capture on a live interface."""
import argparse,hashlib,ipaddress,json,pathlib,sqlite3,struct,subprocess,tempfile,unittest
from core import SCHEMA,dbopen,build_sessions,Matcher,ns,classify,correlate,endpoints,parse_radius,traffic,putmeta,executable
from report import write_report,table,profile
from server import isolated_capture

def radius_row(frame,t,status='3',age=10,ip='10.0.0.2',acct='s1',name='Vessel-A',user='alice',ctx='',nas='10.0.0.1',input_bytes=100):
 return (frame,ns(t),nas,'10.0.0.254',ctx,'4',status,user,'aa:bb',name,nas,name,acct,json.dumps([ip]) if ip else '[]',age,0,'',input_bytes,200,'[]',None,None)
def insert_radius(db,*rows):db.executemany('INSERT INTO radius VALUES('+','.join('?'*22)+')',rows);db.commit()
def packet(db,frame,t,src,dst,sport,dport,tr,app,fields,direction='upload',sid=1,vid=1):
 raw={'frame.number':[str(frame)],'frame.time_epoch':[str(t)],'frame.protocols':['ip:'+tr.lower()+':'+app],**fields}
 db.execute('INSERT INTO packets VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',(frame,ns(t),100,100,src,str(sport),dst,str(dport),tr,app,'ip:'+tr.lower()+':'+app,'',json.dumps(raw)))
 db.execute('INSERT INTO links VALUES(?,?,?,?,?,?,?,?,NULL)',(frame,vid,sid,1,direction,'external','Medium','test assignment'))

class CorrelationTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.path=pathlib.Path(self.tmp.name);self.db=dbopen(self.path/'t.sqlite');self.db.executescript(SCHEMA)
 def tearDown(self):self.db.close();self.tmp.cleanup()
 def test_no_uptime_backfill_and_no_open_ended_assignment(self):
  insert_radius(self.db,radius_row(1,100,age=90));build_sessions(self.db);a=dict(self.db.execute('SELECT * FROM assignments').fetchone());m=Matcher([a])
  self.assertEqual(a['start'],ns(100));self.assertFalse(m.lookup('10.0.0.2',ns(99),''));self.assertFalse(m.lookup('10.0.0.2',ns(101),''));self.assertEqual(len(m.lookup('10.0.0.2',ns(100),'')),1)
 def test_reused_private_ip_and_context_collision(self):
  insert_radius(self.db,radius_row(1,10,'1',0),radius_row(2,20,'2',10),radius_row(3,15,'1',0,acct='s2',name='Vessel-B',user='bob'),radius_row(4,25,'2',10,acct='s2',name='Vessel-B',user='bob'));build_sessions(self.db)
  m=Matcher(self.db.execute('SELECT * FROM assignments'));self.assertEqual(len(m.lookup('10.0.0.2',ns(17),'')),2);self.assertEqual(len(m.lookup('10.0.0.2',ns(23),'')),1);self.assertFalse(m.lookup('10.0.0.2',ns(17),'other namespace'))
 def test_dynamic_ip_gap_and_session_id_reuse(self):
  insert_radius(self.db,radius_row(1,10,'1',0),radius_row(2,20,age=10),radius_row(3,25,age=15,ip='10.0.0.3'),radius_row(4,30,'2',20,ip='10.0.0.3'),radius_row(5,40,'1',0),radius_row(6,50,'2',10));build_sessions(self.db)
  self.assertEqual(self.db.execute('SELECT count(*) FROM sessions').fetchone()[0],2);m=Matcher(self.db.execute('SELECT * FROM assignments'));self.assertFalse(m.lookup('10.0.0.2',ns(23),''));self.assertFalse(m.lookup('10.0.0.3',ns(23),''));self.assertEqual(len(m.lookup('10.0.0.3',ns(27),'')),1)
 def test_nas_reboot_splits_continuity(self):
  insert_radius(self.db,radius_row(1,10),radius_row(2,15,'7'),radius_row(3,20,age=20));build_sessions(self.db)
  self.assertEqual(self.db.execute('SELECT count(*) FROM sessions').fetchone()[0],2)
 def test_group_users_by_site_not_user(self):
  insert_radius(self.db,radius_row(1,10),radius_row(2,11,user='bob',acct='s2'));build_sessions(self.db)
  self.assertEqual(self.db.execute('SELECT count(*) FROM vessels').fetchone()[0],1);self.assertEqual(self.db.execute('SELECT count(*) FROM sessions').fetchone()[0],2)
 def test_radius_retransmission_does_not_extend_assignment(self):
  a=list(radius_row(1,10));b=list(radius_row(2,15))
  raw=json.dumps([{'name':'radius.authenticator','show':'aabbccdd'},{'name':'radius.id','show':'7'}]);a[19]=raw;b[19]=raw
  insert_radius(self.db,tuple(a),tuple(b));build_sessions(self.db)
  self.assertEqual(self.db.execute('SELECT start=end FROM assignments').fetchone()[0],1);self.assertEqual(self.db.execute('SELECT count(DISTINCT session_id) FROM radius').fetchone()[0],1)
 def test_layer_alignment_and_suffix_boundaries(self):
  d={'frame.protocols':['ip:udp:l2tp:ppp:ipv6:tcp:tls'],'ip.src':['1.2.3.4'],'ip.dst':['5.6.7.8'],'ipv6.src':['2001:db8::1'],'ipv6.dst':['2001:db8::2'],'tcp.srcport':['2345'],'tcp.dstport':['443'],'udp.srcport':['1701']}
  self.assertEqual(endpoints(d)[:6],('2001:db8::1','2345','2001:db8::2','443','TCP','tls'));self.assertEqual(classify('youtube.com.evil.test','tls'),'Web / named endpoint');self.assertEqual(classify('r1.googlevideo.com','quic'),'YouTube');self.assertEqual(classify('','tls'),'Unknown')
  quoted={'frame.protocols':['ip:icmp:ip:udp'],'ip.src':['8.8.8.8','10.0.0.2'],'ip.dst':['1.1.1.1','8.8.8.8'],'udp.srcport':['5000']}
  self.assertEqual(endpoints(quoted)[:6],('8.8.8.8','','1.1.1.1','','ICMP','icmp'))
 def test_dns_tls_temporal_chain_and_bytes(self):
  insert_radius(self.db,radius_row(1,10,'1',0),radius_row(2,100,'2',90));build_sessions(self.db)
  packet(self.db,3,20,'10.0.0.2','8.8.8.8',5000,53,'UDP','dns',{'udp.stream':['1'],'dns.qry.name':['youtube.com'],'dns.qry.type':['1'],'dns.flags.response':['0']})
  packet(self.db,4,21,'8.8.8.8','10.0.0.2',53,5000,'UDP','dns',{'udp.stream':['1'],'dns.qry.name':['youtube.com'],'dns.qry.type':['1'],'dns.flags.response':['1'],'dns.flags.rcode':['0'],'dns.response_to':['3'],'dns.a':['8.7.6.5'],'dns.resp.ttl':['30']},direction='download')
  packet(self.db,5,22,'10.0.0.2','8.7.6.5',6000,443,'TCP','tls',{'tcp.stream':['1'],'tls.handshake.extensions_server_name':['youtube.com']})
  packet(self.db,6,23,'8.7.6.5','10.0.0.2',443,6000,'TCP','tls',{'tcp.stream':['1']},direction='download')
  packet(self.db,7,80,'10.0.0.2','8.7.6.5',6001,443,'TCP','tls',{'tcp.stream':['2']})
  correlate(self.db);f=self.db.execute("SELECT * FROM flows WHERE service='YouTube'").fetchone();self.assertEqual(f['bytes'],200);self.assertEqual(f['bytes_up'],100);self.assertEqual(f['bytes_down'],100);self.assertEqual(f['confidence'],'High');self.assertIn('query_frame',f['evidence']);self.assertEqual(self.db.execute('SELECT service FROM flows WHERE local_port=?',('6001',)).fetchone()[0],'Unknown')
  write_report(self.db,self.path/'report.html');self.assertIn('Vessel Network Intelligence',(self.path/'report.html').read_text(encoding='utf8'))
 def test_quic_same_connection_and_session_scoping(self):
  packet(self.db,3,20,'10.0.0.2','8.7.6.5',5000,443,'UDP','quic',{'udp.stream':['1'],'quic.connection.number':['2'],'quic.dcid':['abcd'],'tls.handshake.extensions_server_name':['youtube.com']})
  packet(self.db,4,21,'8.7.6.5','10.0.0.2',443,5000,'UDP','udp',{'udp.stream':['1']},direction='download')
  packet(self.db,5,22,'10.0.0.2','8.7.6.5',5000,443,'UDP','quic',{'udp.stream':['1'],'quic.connection.number':['2']},sid=2)
  correlate(self.db);self.assertEqual(self.db.execute('SELECT packets FROM flows WHERE session_id=1').fetchone()[0],2);self.assertEqual(self.db.execute('SELECT service FROM flows WHERE session_id=2').fetchone()[0],'Unknown')
 def test_export_original_bytes_and_endian(self):
  def block(t,b):return struct.pack('<II',t,len(b)+12)+b+struct.pack('<I',len(b)+12)
  header=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))+block(1,struct.pack('<HHI',101,0,65535));packets=[block(6,struct.pack('<IIIII',0,0,i,4,4)+bytes([i])*4) for i in (1,2,3)];path=self.path/'input.pcapng';path.write_bytes(header+b''.join(packets))
  self.assertEqual(b''.join(isolated_capture(path,[2])),header+packets[1])
  custom=block(0x40000bad,struct.pack('<I',10949)+b'test')
  path.write_bytes(header+packets[0]+custom+packets[1]+packets[2]);self.assertEqual(b''.join(isolated_capture(path,[3])),header+packets[1])

class TsharkIntegration(unittest.TestCase):
 def test_real_pcap_radius_and_dns(self):
  # Build a valid offline capture with RADIUS Start/Stop and a DNS exchange.
  def avp(t,b):return bytes([t,len(b)+2])+b
  def radius(status,age):
   attrs=avp(1,b'alice')+avp(4,ipaddress.ip_address('10.0.0.1').packed)+avp(8,ipaddress.ip_address('10.0.0.2').packed)+avp(30,b'MV-Test')+avp(31,b'client')+avp(32,b'MV-Test')+avp(40,struct.pack('!I',status))+avp(44,b'test1')+avp(46,struct.pack('!I',age));return struct.pack('!BBH',4,status,len(attrs)+20)+b'\0'*16+attrs
  def udp(src,dst,sp,dp,data):
   u=struct.pack('!HHHH',sp,dp,len(data)+8,0)+data;return struct.pack('!BBHHHBBH4s4s',0x45,0,len(u)+20,0,0,64,17,0,ipaddress.ip_address(src).packed,ipaddress.ip_address(dst).packed)+u
  q=b'\x07youtube\x03com\0'+struct.pack('!HH',1,1);query=struct.pack('!HHHHHH',123,0x0100,1,0,0,0)+q;answer=struct.pack('!HHHHHH',123,0x8180,1,1,0,0)+q+b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+b'\x08\x07\x06\x05'
  with tempfile.TemporaryDirectory() as td:
   out=pathlib.Path(td);pcap=out/'test.pcap';packets=[udp('10.0.0.1','10.0.0.254',1000,1813,radius(1,0)),udp('10.0.0.2','8.8.8.8',5000,53,query),udp('8.8.8.8','10.0.0.2',53,5000,answer),udp('10.0.0.1','10.0.0.254',1000,1813,radius(2,30))]
   with pcap.open('wb') as f:
    f.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,101))
    for i,b in enumerate(packets):f.write(struct.pack('<IIII',100+i*10,0,len(b),len(b))+b)
   pdml=out/'r.xml'
   with pdml.open('wb') as f:subprocess.run([executable('tshark'),'-n','-r',str(pcap),'-Y','radius','-T','pdml'],stdout=f,check=True)
   db=dbopen(out/'a.sqlite');db.executescript(SCHEMA);parse_radius(pdml,db);build_sessions(db);putmeta(db,'log_path',str(out/'tshark.log'));traffic(db,pcap,executable('tshark'),4);correlate(db)
   self.assertEqual(db.execute('SELECT count(*) FROM packets').fetchone()[0],2);self.assertEqual(db.execute('SELECT sum(bytes) FROM flows').fetchone()[0],len(packets[1])+len(packets[2]));self.assertEqual(db.execute('SELECT count(*) FROM dns').fetchone()[0],2);self.assertEqual(db.execute('SELECT header_packets FROM address_visibility').fetchone()[0],2);db.close()

if __name__=='__main__':unittest.main(verbosity=2)
