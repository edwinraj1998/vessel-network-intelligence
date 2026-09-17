"""Satellite profiles derived only from explicit producer telemetry; never from vessel names."""
import collections,hashlib,json

def rows(db,sql,args=()):
 return [dict(r) for r in db.execute(sql,args)]

def catalog(db):
 if not db.execute("SELECT 1 FROM sqlite_master WHERE name='telemetry'").fetchone():return []
 parents=collections.defaultdict(list)
 for r in rows(db,"SELECT * FROM telemetry WHERE kind='communication-session'"):
  raw=json.loads(r['raw']);name=raw.get('satellite-name')
  if isinstance(name,str) and name.strip():parents[(r['section'],r['comm'])].append((name.strip(),r,raw))
 groups={};resolved=set()
 for (section,comm),records in parents.items():
  names={x[0] for x in records}
  if len(names)!=1:continue  # Conflicting definitions cannot identify a satellite.
  resolved.add((section,comm))
  name=next(iter(names));key=hashlib.sha256(name.encode()).hexdigest()[:24]
  g=groups.setdefault(key,dict(id=key,name=name,confidence='Medium',reason='Explicit satellite-name in capture-producer telemetry; physical spacecraft identity is not independently verified.',sessions=[],subnetworks=set(),interfaces=set(),frames=[]))
  g['sessions'].append({'section':section,'communication_session':comm})
  for _,r,raw in records:
   g['frames'].append(r['frame'])
   for field,out in [('satellite-sub-network-name','subnetworks'),('interface','interfaces')]:
    if raw.get(field) is not None:g[out].add(str(raw[field]))
 unresolved=rows(db,"SELECT DISTINCT section,comm FROM telemetry WHERE kind='stream'")
 unresolved=[{'section':r['section'],'communication_session':r['comm']} for r in unresolved if (r['section'],r['comm']) not in resolved]
 if unresolved:groups['unresolved']={'id':'unresolved','name':'Unresolved satellite — terminal telemetry only','confidence':'Unknown','reason':'No unambiguous satellite-name definition for these communication sessions; this is a coverage bucket, not a spacecraft identity.','sessions':unresolved,'subnetworks':set(),'interfaces':set(),'frames':[]}
 return [{**g,'subnetworks':sorted(g['subnetworks']),'interfaces':sorted(g['interfaces']),'frames':sorted(set(g['frames']))} for g in sorted(groups.values(),key=lambda x:x['name'])]

def profile(db,key):
 sat=next((x for x in catalog(db) if x['id']==key),None)
 if not sat:raise ValueError('Unknown satellite profile')
 telemetry=[];mappings=[];terminals=set();bands=set();spots=set();positions=[]
 for session in sat['sessions']:
  args=(session['section'],session['communication_session'])
  for r in rows(db,'SELECT * FROM telemetry WHERE section=? AND comm=? ORDER BY frame',args):
   r['raw']=json.loads(r['raw']);telemetry.append(r);raw=r['raw']
   for field,bucket in [('frequency-band',bands),('satellite-spot',spots)]:
    if raw.get(field) is not None:bucket.add(str(raw[field]))
   for role in ('source','destination'):
    entity=raw.get(role,{})
    if isinstance(entity,dict) and entity.get('type')=='user-terminal':
     if entity.get('id') is not None:terminals.add(str(entity['id']))
     for field in ('location','position','latitude','longitude'):
      if entity.get(field) is not None:positions.append({'frame':r['frame'],'role':role,'terminal':entity.get('id'),'field':field,'observed_value':entity[field]})
  mappings+=rows(db,'SELECT m.*,v.name vessel_name FROM satellite_mapping m JOIN vessels v ON v.id=m.vessel_id WHERE m.section=? AND m.comm=?',args)
 ids=[-m['id'] for m in mappings];stats={'packets':0,'bytes':0};protocols=[];timeline=[];destinations=[]
 if ids:
  marks=','.join('?' for _ in ids);where=f'frame IN (SELECT frame FROM links WHERE session_id IN ({marks}))'
  stats=dict(db.execute('SELECT count(*) packets,coalesce(sum(length),0) bytes,min(t) first_seen,max(t) last_seen FROM packets WHERE '+where,ids).fetchone())
  protocols=rows(db,'SELECT application,count(*) packets,sum(length) bytes FROM packets WHERE '+where+' GROUP BY application ORDER BY bytes DESC',ids)
  timeline=rows(db,'SELECT (t/10000000000)*10000000000 t,count(*) packets,sum(length) bytes FROM packets WHERE '+where+' GROUP BY 1 ORDER BY 1',ids)
  destinations=rows(db,'SELECT dst,dport,transport,count(*) packets,sum(length) bytes FROM packets WHERE '+where+' GROUP BY dst,dport,transport ORDER BY bytes DESC LIMIT 50',ids)
 return {'satellite':sat,'terminals':sorted(terminals),'frequency_bands':sorted(bands),'spots':sorted(spots),'terminal_positions':positions,'mappings':mappings,'telemetry':telemetry,'stats':stats,'protocols':protocols,'timeline':timeline,'destinations':destinations,'coverage':'Traffic totals cover existing unambiguous vessel/terminal mappings only, not all satellite traffic. Telemetry lists all named communication sessions, including streams without vessel attribution.','unknown':{'orbital_slot':'Unknown','NORAD_ID':'Unknown','operator':'Unknown','active_RF_path':'Not independently verified'},'evidence_policy':'Names and RF metadata are producer assertions preserved from the PCAP. Parent joins require matching capture section and communication-session ID. Conflicting satellite names exclude that session.'}
