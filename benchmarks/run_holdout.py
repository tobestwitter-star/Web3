from __future__ import annotations
import json,sys,time,traceback,tempfile,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from bounty_engine import build_report
from research_pipeline import ResearchPipeline
from candidate_triage import triage_finding
STATUS='UNVERIFIED — HUMAN REVIEW REQUIRED'

def expected_hit(f,e):
 t=' '.join(str(f.get(k,'')) for k in ('title','description','hypothesis','category','root_cause','kind')).lower()
 return any(x.lower().replace('_',' ') in t or x.lower() in t for x in e)

def run_fixture(p,fx):
 src=ROOT/'benchmarks'/'holdout'/fx['file'];start=time.perf_counter();r={'fixture':fx['name'],'expected':fx['expected'],'safe':fx['safe'],'status':STATUS}
 try:
  code=src.read_text();opp={'id':'holdout:'+fx['name'],'source':'offline-holdout','name':fx['name'],'url':'file://'+str(src),'status':'active','max_bounty_usd':0,'scope_size':1,'source_code_available':True,'authorization_confirmed':True,'scope_notes':'Isolated local holdout; explicitly authorized.','metadata':{'holdout':True}}
  plan=p.plan(opp,'Local holdout: '+str(src));r['discovery']=bool(plan.get('targets'))
  with tempfile.TemporaryDirectory(prefix='web3-holdout-') as td:
   root=Path(td);shutil.copy2(src,root/src.name);a=p.analyze_local(str(root),fx['name'],code,True,['slither','aderyn','wake'],opp)
  fs=[triage_finding(dict(f),code) for f in a.get('correlated_findings',[])]
  r.update({'analysis_status':a.get('status'),'attack_paths':a.get('attack_paths',[]),'findings':fs,'tool_results':a.get('tool_results',{}),'symbolic':a.get('symbolic_validation',{}),'invariants':a.get('invariant_validation',{}),'upgrade_surface':a.get('upgrade_surface',{})})
  hit=set()
  for f in fs:
   if not f.get('bounty_candidate',True):
    continue
   for e in fx['expected']:
    if expected_hit(f,[e]):hit.add(e)
  r['detected']=sorted(hit);r['missed']=[e for e in fx['expected'] if e not in hit];r['false_positives']=sum(1 for f in fs if fx['safe'] and f.get('bounty_candidate',True))
  r['evidence_quality']={'finding_count':len(fs),'bounty_candidates':sum(bool(f.get('bounty_candidate',True)) for f in fs),'with_source_location':sum(bool(f.get('location')) for f in fs),'with_evidence':sum(bool(f.get('evidence')) for f in fs),'with_attack_path':sum(bool(f.get('attack_paths')) for f in fs),'with_execution_evidence':sum(bool(f.get('execution_evidence')) for f in fs),'all_unverified':all(f.get('status')==STATUS for f in fs)}
  r['reproducibility']=[f.get('reproducibility',0) for f in fs];r['reports']=build_report(fs,opp);r['report_count']=len(r['reports'].get('findings',[]))
  tool_results=a.get('tool_results',[]);tool_items=tool_results.get('results',[]) if isinstance(tool_results,dict) else tool_results
  r['tool_coverage']={x.get('name',x.get('tool','unknown')):('skipped' if x.get('skipped') else 'executed') for x in tool_items if isinstance(x,dict)};r['elapsed_seconds']=round(time.perf_counter()-start,3);r['result']='ok'
 except Exception as e:r.update({'result':'error','error':str(e),'traceback':traceback.format_exc()})
 return r

def main():
 m=json.loads((ROOT/'benchmarks/holdout/holdout_manifest.json').read_text());p=ResearchPipeline();rs=[run_fixture(p,x) for x in m['fixtures']];v=[x for x in rs if not x['safe']];s=[x for x in rs if x['safe']];exp=sum(len(x['expected']) for x in v);det=sum(len(x.get('detected',[])) for x in v);fp=sum(x.get('false_positives',0) for x in s);miss=exp-det;summary={'fixtures':len(rs),'vulnerable_fixtures':len(v),'safe_controls':len(s),'expected_labels':exp,'detected_labels':det,'missed_labels':miss,'false_positive_findings':fp,'precision':round(det/(det+fp),4) if det+fp else 0,'recall':round(det/exp,4) if exp else 0,'errors':sum(x.get('result')=='error' for x in rs),'all_findings_unverified':all(f.get('status')==STATUS for x in rs for f in x.get('findings',[]))};payload={'benchmark':'Web3 BugHunter unseen holdout','version':m['version']+1,'summary':summary,'fixtures':rs,'status':STATUS};out=ROOT/'benchmarks/results';out.mkdir(exist_ok=True);(out/'holdout.json').write_text(json.dumps(payload,indent=2,default=str));(out/'holdout.md').write_text('# Web3 BugHunter Unseen Holdout\n\nStatus: '+STATUS+'\n\n## Summary\n'+''.join(f'\n- **{k}**: {v}' for k,v in summary.items())+'\n',encoding='utf-8');print(json.dumps(summary,indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
