"""Read-only artifact queries, separate from vessel attribution."""
import json,pathlib,re
from report import rows,metadata

def listing(db,vid,q):
 m=metadata(db);scope=q.get('scope','vessel');args=[]
 if not db.execute("SELECT 1 FROM sqlite_master WHERE name='artifacts'").fetchone():return {'rows':[],'total':0,'counts':[],'status':m.get('reconstruction_status','Pending reconstruction'),'scope':scope}
 clauses=[]
 if scope!='capture':clauses.append('EXISTS (SELECT 1 FROM artifact_links l WHERE l.artifact_id=a.id AND l.vessel_id=?)');args.append(vid)
 if q.get('category'):clauses.append('a.kind=?');args.append(q['category'])
 if q.get('q'):clauses.append('(a.name LIKE ? OR a.detail LIKE ? OR a.preview LIKE ? OR a.src LIKE ? OR a.dst LIKE ?)');args+=['%'+q['q']+'%']*5
 where=' WHERE '+' AND '.join(clauses) if clauses else ''
 base=' FROM artifacts a'+where
 total=db.execute('SELECT count(*)'+base,args).fetchone()[0]
 result=rows(db,"SELECT a.id,a.kind,a.frame,a.t,a.name,a.mime,a.size,a.status,a.confidence,a.src,a.dst,a.path!='' downloadable,(SELECT group_concat(DISTINCT vessel_id) FROM artifact_links l WHERE l.artifact_id=a.id) vessel_ids"+base+' ORDER BY a.frame LIMIT 100 OFFSET ?',args+[max(0,int(q.get('offset','0')))])
 counts=rows(db,'SELECT a.kind,count(*) n'+base+' GROUP BY a.kind',args)
 return {'rows':result,'total':total,'counts':counts,'status':m.get('reconstruction_status','Pending'),'scope':scope}

def detail(db,aid,vid,q):
 a=db.execute('SELECT * FROM artifacts WHERE id=?',(aid,)).fetchone()
 if not a:raise ValueError('Unknown artifact')
 links=rows(db,'SELECT * FROM artifact_links WHERE artifact_id=?',(aid,))
 if q.get('scope')!='capture' and not any(x['vessel_id']==vid for x in links):raise ValueError('Artifact is not attributed to this vessel; use explicit whole-capture scope')
 obj=dict(a);obj.pop('path');obj['detail']=json.loads(obj['detail']);obj['frames']=json.loads(obj['frames']);obj['attribution']=links;obj['source_filename']=metadata(db).get('filename');obj['source_sha256']=metadata(db).get('sha256')
 return obj,a

def serve_file(handler,db,dbpath,aid,vid,q):
 obj,a=detail(db,aid,vid,q)
 if not re.fullmatch(r'[a-f0-9]{64}\.bin',a['path']):raise ValueError('No stored bytes available')
 p=dbpath.parent/'reconstructed'/a['path'];size=p.stat().st_size
 # Only signature-confirmed passive media is eligible for inline preview.
 with p.open('rb') as fp:head=fp.read(256)
 from reconstruction import media_type
 kind,mime=media_type(head,'application/octet-stream')
 inline=q.get('inline')=='1' and kind in ('Image','Video')
 if inline and mime not in ('image/png','image/jpeg','image/gif','image/webp','video/mp4','video/webm'):raise ValueError('This format cannot be safely previewed')
 start=0;end=size-1;partial=False
 if handler.headers.get('Range'):
  match=re.fullmatch(r'bytes=(\d+)-(\d*)',handler.headers['Range'])
  if not match:handler.send_error(416);return
  start=int(match[1]);end=min(end,int(match[2])) if match[2] else end;partial=True
  if start>end or start>=size:handler.send_error(416);return
 handler.send_response(206 if partial else 200);handler.send_header('Content-Type',mime if inline else 'application/octet-stream');handler.send_header('Content-Length',str(max(0,end-start+1)));handler.send_header('Accept-Ranges','bytes');handler.send_header('X-Content-Type-Options','nosniff');handler.send_header('Cache-Control','no-store');handler.send_header('Content-Security-Policy',"default-src 'none'; sandbox");handler.send_header('Referrer-Policy','no-referrer')
 if partial:handler.send_header('Content-Range',f'bytes {start}-{end}/{size}')
 if not inline:handler.send_header('Content-Disposition',f'attachment; filename="artifact-{aid}'+('.eml' if a['kind']=='Email' else '.bin')+'"')
 handler.end_headers()
 with p.open('rb') as fp:
  fp.seek(start);remaining=end-start+1
  while remaining>0:
   b=fp.read(min(1024*1024,remaining))
   if not b:break
   handler.wfile.write(b);remaining-=len(b)
