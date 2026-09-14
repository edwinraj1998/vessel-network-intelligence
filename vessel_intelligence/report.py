"""Local report query layer; every aggregate can be traced to stored frames."""
import json,pathlib,urllib.parse
from core import dumps

def rows(db,sql,args=()):return [dict(r) for r in db.execute(sql,args)]
def metadata(db):return {r['key']:json.loads(r['value']) for r in db.execute('SELECT * FROM meta')}
def catalog(db):
 result=rows(db,'''SELECT v.*, (SELECT count(*) FROM sessions s WHERE s.vessel_id=v.id) sessions,
 (SELECT group_concat(DISTINCT username) FROM radius r WHERE r.vessel_id=v.id AND username!='') usernames,
 (SELECT group_concat(DISTINCT calling_station) FROM radius r WHERE r.vessel_id=v.id AND calling_station!='') calling_stations,
 (SELECT group_concat(DISTINCT ip) FROM assignments a WHERE a.vessel_id=v.id) ips,
 (SELECT min(t) FROM radius r WHERE r.vessel_id=v.id) first_seen,
 (SELECT max(t) FROM radius r WHERE r.vessel_id=v.id) last_seen,
 (SELECT coalesce(sum(bytes),0) FROM flows f WHERE f.vessel_id=v.id) bytes FROM vessels v ORDER BY name''')
 for v in result:v['marine_url']='https://www.marinetraffic.com/en/ais/index/search/all?keyword='+urllib.parse.quote(v['imo'] or v['mmsi'] or v['name'])
 return {'meta':metadata(db),'vessels':result,'capture_protocols':rows(db,'SELECT * FROM capture_protocols ORDER BY bytes DESC'),'address_visibility':rows(db,'SELECT * FROM address_visibility ORDER BY header_packets DESC'),'audit_count':db.execute('SELECT count(*) FROM audit').fetchone()[0]}

QUERIES={
 'satellite':'''SELECT m.*,t.frame telemetry_frame,t.t_ns telemetry_timestamp_ns,json_extract(t.raw,'$.frequency-band') frequency_band,json_extract(t.raw,'$.tap-location') tap_location,coalesce(json_extract(t.raw,'$.source.position.latitude'),json_extract(t.raw,'$.destination.position.latitude')) latitude,coalesce(json_extract(t.raw,'$.source.position.longitude'),json_extract(t.raw,'$.destination.position.longitude')) longitude,(SELECT json_extract(c.raw,'$.satellite-name') FROM telemetry c WHERE c.kind='communication-session' AND c.section=m.section AND c.comm=m.comm LIMIT 1) satellite_name,t.raw FROM satellite_mapping m JOIN telemetry t ON t.section=m.section AND t.comm=m.comm AND t.stream=m.stream WHERE m.vessel_id=?''',
 'diagnostics':'''SELECT * FROM diagnostics WHERE vessel_id=?''',
 'profile': 'SELECT * FROM vessels WHERE id=?',
 'sessions': '''SELECT s.*, (SELECT group_concat(DISTINCT ip) FROM assignments a WHERE a.session_id=s.id) assigned_ips,(end-start)/1000000000.0 observed_duration_seconds FROM sessions s WHERE vessel_id=?''',
 'assignments':'SELECT * FROM assignments WHERE vessel_id=?',
 'exclusions':'''SELECT a.* FROM audit a WHERE EXISTS (SELECT 1 FROM json_each(coalesce(json_extract(a.detail,'$.candidate_session_ids'),json_extract(a.detail,'$.session_ids'),'[]')) j JOIN sessions s ON s.id=j.value WHERE s.vessel_id=?)''',
 'visibility':'''SELECT v.* FROM address_visibility v WHERE ip IN (SELECT ip FROM assignments WHERE vessel_id=?)''',
 'identities':'''SELECT frame,t,username,calling_station,called_station,nas,nas_name,acct_id,ips,status,src,dst,context,session_id,input_bytes,output_bytes,age,delay,event_time,raw FROM radius WHERE vessel_id=?''',
 'dns':'SELECT * FROM dns WHERE vessel_id=?',
 'tls':'SELECT * FROM tls WHERE vessel_id=?',
 'flows':'SELECT *, (last_seen-first_seen)/1000000000.0 duration_seconds FROM flows WHERE vessel_id=?',
 'protocols':'''SELECT p.application protocol,count(DISTINCT l.flow_id) connections,count(*) packets,sum(p.length) bytes,sum(CASE direction WHEN 'upload' THEN p.length ELSE 0 END) upload,sum(CASE direction WHEN 'download' THEN p.length ELSE 0 END) download,min(t) first_seen,max(t) last_seen FROM packets p JOIN links l ON l.frame=p.frame WHERE l.vessel_id=? GROUP BY p.application ORDER BY bytes DESC''',
 'domains':'''WITH names AS (SELECT query domain FROM dns WHERE vessel_id=? AND query!='' UNION SELECT domain FROM flows WHERE vessel_id=? AND domain!=''), d AS (SELECT query,count(DISTINCT CASE WHEN is_response=0 THEN frame END) dns_queries,group_concat(DISTINCT nullif(answer_ip,'')) resolved_ips,min(t) dns_first,max(t) dns_last FROM dns WHERE vessel_id=? GROUP BY query), f AS (SELECT domain,group_concat(DISTINCT service) service,count(*) connections,sum(packets) packets,sum(bytes) bytes,sum(bytes_up) upload,sum(bytes_down) download,min(first_seen) first_seen,max(last_seen) last_seen,group_concat(DISTINCT confidence) confidence FROM flows WHERE vessel_id=? GROUP BY domain) SELECT n.domain,coalesce(d.dns_queries,0) dns_queries,d.resolved_ips,f.service,coalesce(f.connections,0) connections,coalesce(f.packets,0) packets,coalesce(f.bytes,0) bytes,coalesce(f.upload,0) upload,coalesce(f.download,0) download,coalesce(f.first_seen,d.dns_first) first_seen,coalesce(f.last_seen,d.dns_last) last_seen,f.confidence FROM names n LEFT JOIN d ON d.query=n.domain LEFT JOIN f ON f.domain=n.domain ORDER BY bytes DESC''',
 'destinations':'''SELECT remote_ip destination_ip,remote_port port,transport,application,domain,service,count(*) connections,sum(packets) packets,sum(bytes) bytes,min(first_seen) first_seen,max(last_seen) last_seen FROM flows WHERE vessel_id=? GROUP BY remote_ip,remote_port,transport,application,domain,service ORDER BY bytes DESC''',
 'services':'''SELECT service,count(*) connections,sum(packets) packets,sum(bytes) bytes,sum(bytes_up) upload,sum(bytes_down) download,group_concat(DISTINCT confidence) confidence FROM flows WHERE vessel_id=? GROUP BY service ORDER BY bytes DESC''',
 'traffic':'''SELECT p.*,l.session_id,l.assignment_id,l.direction,l.scope,l.confidence,l.reason,l.flow_id,f.domain,f.service FROM packets p JOIN links l ON p.frame=l.frame LEFT JOIN flows f ON f.id=l.flow_id WHERE l.vessel_id=?''',
 'timeline':'''SELECT p.frame,p.t,p.src,p.sport,p.dst,p.dport,p.application,p.length,l.session_id,l.direction,f.domain,f.service,l.flow_id FROM packets p JOIN links l ON p.frame=l.frame LEFT JOIN flows f ON f.id=l.flow_id WHERE l.vessel_id=? UNION ALL SELECT frame,t,src,'',dst,'','RADIUS '||CASE status WHEN '1' THEN 'Start' WHEN '2' THEN 'Stop' WHEN '3' THEN 'Interim' ELSE code END,0,session_id,'control','','',NULL FROM radius WHERE vessel_id=? ORDER BY t''',
}
def query(db,kind,vid,filters=None):
 if kind not in QUERIES:raise ValueError('Unknown table')
 sql=QUERIES[kind];args=[vid]*sql.count('?')
 filters=filters or {};clauses=[]
 columns=[r[0] for r in db.execute('SELECT * FROM ('+sql+') LIMIT 0',args).description]
 if filters.get('q'):
  clauses.append('('+' OR '.join('CAST("'+c+'" AS TEXT) LIKE ?' for c in columns)+')');args+=['%'+filters['q']+'%']*len(columns)
 mapping={'protocol':'application','service':'service','domain':'domain','destination':'dst','session':'session_id'}
 for name,column in mapping.items():
  if filters.get(name) and column in columns:clauses.append('"'+column+'" LIKE ?');args.append('%'+filters[name]+'%')
 for name,op in [('from','>='),('to','<=')]:
  if filters.get(name) and 't' in columns:clauses.append('t '+op+' ?');args.append(int(filters[name]))
 return 'SELECT * FROM ('+sql+')'+(' WHERE '+' AND '.join(clauses) if clauses else ''),args

def table(db,kind,vid,filters=None,limit=200,offset=0):
 if kind in ('satellite','diagnostics') and not db.execute("SELECT 1 FROM sqlite_master WHERE name=?",('satellite_mapping' if kind=='satellite' else 'diagnostics',)).fetchone():return {'rows':[],'total':0,'offset':offset,'limit':limit}
 sql,args=query(db,kind,vid,filters);total=db.execute('SELECT count(*) FROM ('+sql+')',args).fetchone()[0]
 return {'rows':rows(db,sql+' LIMIT ? OFFSET ?',args+[limit,offset]),'total':total,'offset':offset,'limit':limit}

def profile(db,vid):
 v=next((v for v in catalog(db)['vessels'] if v['id']==vid),None)
 if not v:raise ValueError('Unknown vessel')
 k=dict(db.execute('''SELECT count(*) connections,coalesce(sum(packets),0) packets,coalesce(sum(bytes),0) bytes,coalesce(sum(bytes_up),0) upload,coalesce(sum(bytes_down),0) download,coalesce(sum(bytes_internal),0) internal,count(DISTINCT remote_ip) destinations,count(DISTINCT nullif(domain,'')) domains,count(DISTINCT service) services,count(DISTINCT application) protocols FROM flows WHERE vessel_id=?''',(vid,)).fetchone())
 k['sessions']=v['sessions'];k['ips']=db.execute('SELECT count(DISTINCT ip) FROM assignments WHERE vessel_id=?',(vid,)).fetchone()[0]
 k['attribution']=rows(db,"SELECT CASE WHEN l.session_id<0 THEN 'Terminal bearer candidate' ELSE 'RADIUS assignment' END basis,count(*) packets,sum(p.length) bytes FROM packets p JOIN links l ON l.frame=p.frame WHERE l.vessel_id=? GROUP BY basis",(vid,))
 bins=rows(db,'''SELECT (p.t/1000000000/10)*10 second,sum(p.length) bytes,sum(CASE l.direction WHEN 'upload' THEN p.length ELSE 0 END) upload,sum(CASE l.direction WHEN 'download' THEN p.length ELSE 0 END) download FROM packets p JOIN links l ON p.frame=l.frame WHERE l.vessel_id=? GROUP BY second ORDER BY second''',(vid,))
 hourly=rows(db,'''SELECT (p.t/1000000000/3600)*3600 hour,sum(p.length) bytes FROM packets p JOIN links l ON p.frame=l.frame WHERE l.vessel_id=? GROUP BY hour ORDER BY hour''',(vid,))
 session_usage=rows(db,'''SELECT s.id session_id,s.acct_id,coalesce(sum(f.bytes),0) bytes FROM sessions s LEFT JOIN flows f ON f.session_id=s.id WHERE s.vessel_id=? GROUP BY s.id''',(vid,))
 transport=rows(db,'SELECT transport protocol,sum(bytes) bytes,sum(packets) packets FROM flows WHERE vessel_id=? GROUP BY transport',(vid,))
 ext=rows(db,'SELECT * FROM external WHERE vessel_id=?',(vid,))
 protocol_time=rows(db,'''SELECT (p.t/1000000000/10)*10 second,p.application protocol,sum(p.length) bytes FROM packets p JOIN links l ON p.frame=l.frame WHERE l.vessel_id=? GROUP BY second,protocol ORDER BY second''',(vid,))
 ports=rows(db,'SELECT remote_port port,sum(bytes) bytes,count(*) connections FROM flows WHERE vessel_id=? GROUP BY remote_port ORDER BY bytes DESC LIMIT 20',(vid,))
 return {'vessel':v,'kpis':k,'bins':bins,'hourly':hourly,'session_usage':session_usage,'transport':transport,'protocol_time':protocol_time,'ports':ports,'external':ext[0] if ext else None}

def evidence(db,vid,frame=None,flow=None,session=None,offset=0):
 result={'source_filename':metadata(db).get('filename'),'source_sha256':metadata(db).get('sha256')}
 if frame:
  result['packet']=rows(db,'SELECT p.*,l.* FROM packets p JOIN links l ON l.frame=p.frame WHERE p.frame=? AND l.vessel_id=?',(frame,vid))
  result['radius']=rows(db,'SELECT * FROM radius WHERE frame=? AND vessel_id=?',(frame,vid))
  for r in result['packet']:flow=r['flow_id'];session=r['session_id']
  for r in result['radius']:session=r['session_id']
 if flow:
  result['flow']=rows(db,'SELECT * FROM flows WHERE id=? AND vessel_id=?',(flow,vid))
  if result['flow']:session=result['flow'][0]['session_id']
  result['supporting_packets']=rows(db,'SELECT p.frame,p.t,p.src,p.sport,p.dst,p.dport,p.application,p.length,l.direction,l.session_id FROM packets p JOIN links l ON p.frame=l.frame WHERE l.flow_id=? AND l.vessel_id=? ORDER BY p.frame LIMIT 100 OFFSET ?',(flow,vid,offset))
  result['supporting_packets_total']=db.execute('SELECT count(*) FROM links WHERE flow_id=? AND vessel_id=?',(flow,vid)).fetchone()[0]
 if session:
  if session<0:
   result['attribution_level']='Terminal bearer candidate; individual RADIUS subscriber unknown'
   result['satellite_mapping']=rows(db,'SELECT * FROM satellite_mapping WHERE id=? AND vessel_id=?',(-session,vid))
   if result['satellite_mapping']:
    m=result['satellite_mapping'][0];result['telemetry']=rows(db,'SELECT * FROM telemetry WHERE section=? AND comm=? AND stream=?',(m['section'],m['comm'],m['stream']))
    result['radius']=rows(db,'SELECT * FROM radius WHERE frame IN (SELECT value FROM json_each(?))',(m['radius_frames'],))
   return result
  result['session']=rows(db,'SELECT * FROM sessions WHERE id=? AND vessel_id=?',(session,vid));result['assignments']=rows(db,'SELECT * FROM assignments WHERE session_id=? AND vessel_id=?',(session,vid));result['radius']=rows(db,'SELECT * FROM radius WHERE session_id=? AND vessel_id=?',(session,vid))
 return result

def write_report(db,path):
 bundle=catalog(db);bundle['profiles']={};bundle['tables']={};bundle['evidence']={}
 for v in bundle['vessels']:
  vid=v['id'];bundle['profiles'][str(vid)]=profile(db,vid);bundle['tables'][str(vid)]={k:table(db,k,vid,limit=500) for k in QUERIES}
  # Snapshot preserves all session evidence; full packet pagination stays in local server.
  bundle['evidence'][str(vid)]={str(r['id']):evidence(db,vid,session=r['id']) for r in db.execute('SELECT id FROM sessions WHERE vessel_id=? LIMIT 100',(vid,))}
  if db.execute("SELECT 1 FROM sqlite_master WHERE name='satellite_mapping'").fetchone():
   bundle['evidence'][str(vid)].update({str(-r['id']):evidence(db,vid,session=-r['id']) for r in db.execute('SELECT id FROM satellite_mapping WHERE vessel_id=?',(vid,))})
 template=(pathlib.Path(__file__).parent/'dashboard.html').read_text(encoding='utf8')
 payload=dumps(bundle).replace('<','\\u003c').replace('\u2028','\\u2028').replace('\u2029','\\u2029')
 path.write_text(template.replace('/*BUNDLE*/null',payload),encoding='utf8')
