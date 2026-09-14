import unittest,tempfile,pathlib,sqlite3,json,struct
from satellite import prepare,SCHEMA
from diagnostics import sequence_event

class SatelliteTests(unittest.TestCase):
 def fixture(self,conflict=None):
  tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);root=pathlib.Path(tmp.name)
  def block(t,b):
   b+=b'\0'*((-len(b))%4);return struct.pack('<II',t,len(b)+12)+b+struct.pack('<I',len(b)+12)
  stream={'type':'stream','comm-ses-id':'comm','id':1,'start-time':1700000000000000,'timestamp':1700000000000001,'source':{'type':'user-terminal','id':99}}
  records=[stream]
  if conflict:
   second=json.loads(json.dumps(stream))
   if conflict=='terminal':second['source']['id']=100
   if conflict=='time':second['start-time']+=1
   records.append(second)
  data=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))+block(1,struct.pack('<HHI',101,0,65535))
  for r in records:data+=block(0x40000bad,struct.pack('<I',0)+json.dumps(r).encode())
  comment=json.dumps({'com-ses-id':'comm','stream-id':1}).encode();opts=struct.pack('<HH',1,len(comment))+comment+b'\0'*((-len(comment))%4)+b'\0'*4
  data+=block(6,struct.pack('<IIIII',0,0,0,0,0)+opts);pcap=root/'a.done';pcap.write_bytes(data)
  db=sqlite3.connect(':memory:');db.row_factory=sqlite3.Row;db.executescript(SCHEMA+'CREATE TABLE radius(frame INTEGER,vessel_id INTEGER);');self.addCleanup(db.close)
  db.execute('INSERT INTO radius VALUES(1,1)');pdml=root/'r.xml';text='<pdml><packet><field name="frame.number" show="1"/><field name="frame.section_number" show="1"/><field name="frame.comment" show="{&quot;com-ses-id&quot;:&quot;comm&quot;,&quot;stream-id&quot;:1}"/></packet>'
  if conflict=='vessel':
   db.execute('INSERT INTO radius VALUES(2,2)');text+=text[text.index('<packet>'):].replace('show="1"/><field name="frame.section_number"','show="2"/><field name="frame.section_number"')
  pdml.write_text(text+'</pdml>');prepare(db,pcap,pdml);return db
 def test_exact_annotation_mapping(self):
  db=self.fixture();m=db.execute('SELECT * FROM satellite_mapping').fetchone();self.assertEqual(m['terminal'],'99');self.assertEqual(m['direction'],'upload');self.assertEqual(db.execute('SELECT frame FROM satellite_packets').fetchone()[0],2)
 def test_conflicting_terminals_excluded(self):self.assertEqual(self.fixture('terminal').execute('SELECT count(*) FROM satellite_mapping').fetchone()[0],0)
 def test_reused_stream_with_new_start_excluded(self):self.assertEqual(self.fixture('time').execute('SELECT count(*) FROM satellite_mapping').fetchone()[0],0)
 def test_multiple_vessels_excluded(self):self.assertEqual(self.fixture('vessel').execute('SELECT count(*) FROM satellite_mapping').fetchone()[0],0)
 def test_rtp_wrap_and_anomalies(self):
  self.assertIsNone(sequence_event(65535,0));self.assertEqual(sequence_event(100,103),('rtp_sequence_gap',2));self.assertEqual(sequence_event(100,100)[0],'rtp_duplicate_sequence');self.assertEqual(sequence_event(100,99)[0],'rtp_out_of_order_or_restart')

if __name__=='__main__':unittest.main()
