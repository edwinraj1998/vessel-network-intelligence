"""Rebuild reports, export tables and attach separately sourced external records."""
import argparse,csv,json,pathlib,urllib.parse,datetime
from core import dbopen,dumps
from report import write_report,query,QUERIES

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('database');s=p.add_subparsers(dest='action',required=True)
 s.add_parser('report')
 e=s.add_parser('export');e.add_argument('--vessel',type=int,required=True);e.add_argument('--directory',required=True)
 x=s.add_parser('external');x.add_argument('--vessel',type=int,required=True);x.add_argument('--json',required=True)
 a=p.parse_args();path=pathlib.Path(a.database).resolve();db=dbopen(path)
 if a.action=='external':
  obj=json.loads(pathlib.Path(a.json).read_text(encoding='utf8'));u=urllib.parse.urlsplit(obj['url'])
  if u.scheme!='https' or not (u.hostname=='marinetraffic.com' or (u.hostname or '').endswith('.marinetraffic.com')):raise ValueError('Use an HTTPS MarineTraffic source URL')
  if not obj.get('match_basis') or not obj.get('verified_at') or not isinstance(obj.get('information'),dict):raise ValueError('Required: match_basis, verified_at, information object, url')
  if not db.execute('SELECT 1 FROM vessels WHERE id=?',(a.vessel,)).fetchone():raise ValueError('Unknown vessel ID')
  db.execute('INSERT OR REPLACE INTO external VALUES(?,?,?,?,?,?)',(a.vessel,'MarineTraffic',obj['url'],obj['verified_at'],dumps(obj['information']),obj['match_basis']));db.commit()
 if a.action=='export':
  out=pathlib.Path(a.directory);out.mkdir(parents=True,exist_ok=True)
  for k in QUERIES:
   sql,args=query(db,k,a.vessel);cur=db.execute(sql,args)
   with (out/(k+'.csv')).open('w',encoding='utf-8-sig',newline='') as fp:
    w=csv.writer(fp);w.writerow(['source_filename']+[x[0] for x in cur.description])
    for r in cur:w.writerow(["'"+v if isinstance(v,str) and v.lstrip().startswith(('=','+','-','@')) else v for v in [json.loads(db.execute("SELECT value FROM meta WHERE key='filename'").fetchone()[0])]+list(r)])
 write_report(db,path.parent/'report.html');db.close();print('Report updated:',path.parent/'report.html')
if __name__=='__main__':main()
