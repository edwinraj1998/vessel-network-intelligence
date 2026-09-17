import unittest,sqlite3,json,xml.etree.ElementTree as E,io,wave
from intelligence import SCHEMA,ingest,listing,wav
from satellite import SCHEMA as SAT
from satellite_profiles import catalog,profile

class IntelligenceTests(unittest.TestCase):
 def db(self):
  d=sqlite3.connect(':memory:');d.row_factory=sqlite3.Row;d.executescript(SCHEMA+SAT+'''CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT);CREATE TABLE links(frame INTEGER,vessel_id INTEGER,session_id INTEGER);CREATE TABLE vessels(id INTEGER,name TEXT);CREATE TABLE packets(frame INTEGER,t INTEGER,length INTEGER,application TEXT,dst TEXT,dport TEXT,transport TEXT);''');self.addCleanup(d.close);return d
 def parent(self,d,section,comm,name,frame):
  d.execute('INSERT INTO telemetry VALUES(?,?,?,?,?,?,?,?,?,?)',(frame,section,'communication-session',comm,'',None,None,'','',json.dumps({'satellite-name':name}),))
 def test_satellite_names_never_inferred_from_terminal(self):
  d=self.db();d.execute('INSERT INTO telemetry VALUES(1,0,?,?,?,?,?,?,?,?)',('stream','c','1',None,None,'42','upload',json.dumps({'source':{'type':'user-terminal','id':42}})))
  self.assertEqual(catalog(d)[0]['id'],'unresolved');self.assertEqual(catalog(d)[0]['confidence'],'Unknown')
 def test_conflicting_names_and_cross_section(self):
  d=self.db()
  for frame,section,name in [(1,0,'SAT-A'),(2,0,'SAT-B'),(3,1,'SAT-A')]:
   d.execute('INSERT INTO telemetry VALUES(?,?,?,?,?,?,?,?,?,?)',(frame,section,'communication-session','same','',None,None,'','',json.dumps({'satellite-name':name})))
  c=catalog(d);self.assertEqual(len(c),1);self.assertEqual(c[0]['sessions'],[{'section':1,'communication_session':'same'}])
 def packet(self,frame,t,rtp,seq,pt=0):
  p=E.Element('packet')
  for k,v in {'frame.number':frame,'frame.time_epoch':t,'frame.protocols':'ip:udp:rtp','ip.src':'1.1.1.1','ip.dst':'2.2.2.2','udp.srcport':1000,'udp.dstport':2000,'rtp.ssrc':'42','rtp.seq':seq,'rtp.timestamp':rtp,'rtp.p_type':pt,'rtp.payload':'ff'*160}.items():E.SubElement(p,'field',name=k,show=str(v))
  return p
 def test_audio_gaps_duplicates_and_scope(self):
  d=self.db();ingest(d,self.packet(1,1700000000,0,1));ingest(d,self.packet(2,1700000001,8000,2));ingest(d,self.packet(3,1700000001,8000,2));d.execute('INSERT INTO links VALUES(1,1,9)');stream=d.execute('SELECT stream FROM intelligence_rtp LIMIT 1').fetchone()[0]
  with wave.open(io.BytesIO(wav(d,{'stream':stream})),'rb') as f:self.assertEqual(f.getnframes(),8160)
  with wave.open(io.BytesIO(wav(d,{'stream':stream,'scope':'vessel','vessel':1})),'rb') as f:self.assertEqual(f.getnframes(),160)
  self.assertEqual(listing(d,{'kind':'voip','scope':'vessel','vessel':2})['total'],0)
 def test_rtp_alone_not_cctv_dynamic_audio_not_decoded(self):
  d=self.db();ingest(d,self.packet(1,1700000000,0,1,96));self.assertEqual(listing(d,{'kind':'cctv'})['total'],0);self.assertEqual(d.execute('SELECT count(*) FROM intelligence_rtp').fetchone()[0],0)

if __name__=='__main__':unittest.main()
