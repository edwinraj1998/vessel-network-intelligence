"""Sequence anomalies are capture observations, never proof of network packet loss."""
import json

def sequence_event(previous,current):
 delta=(current-previous)%65536
 if delta==0:return ('rtp_duplicate_sequence',0)
 if delta==1:return None
 if delta<32768:return ('rtp_sequence_gap',delta-1)
 return ('rtp_out_of_order_or_restart',0)

def build(db):
 db.execute("DELETE FROM diagnostics WHERE kind LIKE 'rtp_%'")
 # SQLite keeps stream state off the Python heap even for multi-GB captures.
 db.execute('CREATE TEMP TABLE IF NOT EXISTS rtp_state(key TEXT PRIMARY KEY,seq INTEGER,frame INTEGER)')
 db.execute('DELETE FROM rtp_state')
 for p in db.execute("SELECT p.frame,p.raw,l.vessel_id,l.session_id,l.flow_id,l.direction FROM packets p JOIN links l ON p.frame=l.frame WHERE p.protocols LIKE '%rtp%' ORDER BY p.t,p.frame"):
  d=json.loads(p['raw']);seqs=d.get('rtp.seq',[]);ssrcs=d.get('rtp.ssrc',[])
  if len(seqs)!=1 or len(ssrcs)!=1:continue
  try:seq=int(seqs[0])
  except ValueError:continue
  key=json.dumps([p['vessel_id'],p['session_id'],p['flow_id'],p['direction'],ssrcs[0]])
  old=db.execute('SELECT seq,frame FROM rtp_state WHERE key=?',(key,)).fetchone()
  event=sequence_event(old['seq'],seq) if old else None
  if event:
   raw={'previous_frame':old['frame'],'previous_sequence':old['seq'],'sequence':seq,'ssrc':ssrcs[0],'missing_sequence_positions':event[1],'flow_id':p['flow_id'],'session_id':p['session_id'],'confidence':'Medium for observed sequence anomaly; cause unknown','reason':'May reflect network loss, capture drops, reordering, duplication or sender restart. This is not a measured network loss rate.'}
   db.execute('INSERT INTO diagnostics VALUES(?,?,?,?)',(p['frame'],p['vessel_id'],event[0],json.dumps(raw)))
  # Keep high-water mark for late/duplicate packets; a sender restart remains uncertain.
  if not old or not event or event[0]=='rtp_sequence_gap':db.execute('INSERT OR REPLACE INTO rtp_state VALUES(?,?,?)',(key,seq,p['frame']))
 db.commit()
