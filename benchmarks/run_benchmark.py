from __future__ import annotations
import json,sys,time,traceback,tempfile,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from bounty_engine import build_report
from research_pipeline import ResearchPipeline
STATUS='UNVERIFIED — HUMAN REVIEW REQUIRED'

def expected_hit(finding,expected):
    text=' '.join(str(finding.get(k,'')) for k in ('title','description','hypothesis','category','root_cause')).lower()
    return any(x.lower().replace('_',' ') in text or x.lower() in text for x in expected)

def run_fixture(pipeline,fixture,root):
    name=fixture['name']; source=root/fixture['file']; start=time.perf_counter()
    record={'fixture':name,'expected':fixture['expected'],'safe':fixture['safe'],'stages':{},'status':STATUS}
    try:
        opportunity={'id':'benchmark:'+name,'source':'offline-benchmark','name':name,'url':'file://'+str(source),'status':'active','max_bounty_usd':0,'scope_size':1,'source_code_available':True,'authorization_confirmed':True,'scope_notes':'Deterministic local benchmark fixture; explicitly authorized for local testing.','metadata':{'benchmark':True}}
        code=source.read_text(encoding='utf-8')
        plan=pipeline.plan(opportunity,'Local benchmark scope: '+str(source))
        record['stages']['discovery']=bool(plan.get('targets'))
        record['stages']['scope']=plan.get('scope',{})
        record['stages']['acquisition']={'mode':'isolated_local_fixture','ok':True,'authorized':True}
        with tempfile.TemporaryDirectory(prefix='web3-benchmark-') as td:
            target=Path(td);shutil.copy2(source,target/source.name)
            result=pipeline.analyze_local(str(target),name,code,True,['slither','aderyn','wake'],opportunity)
        record['stages']['analysis_status']=result.get('status');record['stages']['build']=result.get('build')
        record['stages']['protocol_mapping']=result.get('protocol_map',{});record['stages']['attack_paths']=result.get('attack_paths',[])
        record['stages']['external_tools']=result.get('tool_results',{});record['stages']['symbolic']=result.get('symbolic_validation',{})
        record['stages']['invariants']=result.get('invariant_validation',{});record['stages']['upgrade_surface']=result.get('upgrade_surface',{})
        findings=result.get('correlated_findings',[]);record['findings']=findings
        detected=[]
        for f in findings:
            if expected_hit(f,fixture['expected']): detected.extend(fixture['expected'])
        record['detected']=sorted(set(detected));record['missed']=[x for x in fixture['expected'] if x not in record['detected']]
        record['false_positives']=len(findings) if fixture['safe'] else 0
        record['inconclusive']=sum(1 for f in findings if f.get('confidence',0)<.5)
        record['evidence_quality']={'findings':len(findings),'reproducible':sum(1 for f in findings if float(f.get('reproducibility',0))>0),'all_unverified':all(f.get('status')==STATUS for f in findings)}
        record['economic_analysis']=[f.get('economic_analysis',{}) for f in findings[:20]]
        record['reports']=build_report(findings,opportunity)
        record['report_count']=len(record['reports']['findings'])
        record['tool_coverage']={r.get('name'):('skipped' if r.get('skipped') else 'executed') for r in result.get('tool_results',{}).get('results',[])}
        record['elapsed_seconds']=round(time.perf_counter()-start,3);record['result']='ok'
    except Exception as exc:
        record['result']='error';record['error']=str(exc);record['traceback']=traceback.format_exc();record['elapsed_seconds']=round(time.perf_counter()-start,3)
    return record

def summarize(records):
    vuln=[r for r in records if not r['safe']];safe=[r for r in records if r['safe']]
    expected=sum(len(r['expected']) for r in vuln);detected=sum(len(r.get('detected',[])) for r in vuln);missed=expected-detected;fp=sum(r.get('false_positives',0) for r in safe)
    precision=detected/(detected+fp) if detected+fp else 0.0;recall=detected/expected if expected else 0.0
    return {'fixtures':len(records),'vulnerable_fixtures':len(vuln),'safe_controls':len(safe),'expected_labels':expected,'detected_labels':detected,'missed_labels':missed,'false_positive_findings':fp,'precision':round(precision,4),'recall':round(recall,4),'all_findings_unverified':all(f.get('status')==STATUS for r in records for f in r.get('findings',[])),'errors':sum(r.get('result')=='error' for r in records)}

def main():
    manifest=json.loads((ROOT/'benchmarks/manifest.json').read_text());fixture_root=ROOT/'benchmarks/fixtures';pipeline=ResearchPipeline();records=[run_fixture(pipeline,f,fixture_root) for f in manifest['fixtures']]
    summary=summarize(records);payload={'benchmark':'Web3 BugHunter offline benchmark','version':manifest['version'],'summary':summary,'fixtures':records,'status':STATUS}
    out=ROOT/'benchmarks/results';out.mkdir(parents=True,exist_ok=True);(out/'benchmark.json').write_text(json.dumps(payload,indent=2,default=str),encoding='utf-8')
    lines=['# Web3 BugHunter Offline Benchmark','',f'Status: {STATUS}','', '## Summary','']+[f'- **{k}**: {v}' for k,v in summary.items()]+['','## Fixture results','']
    for r in records: lines += [f"### {r['fixture']}",f"- result: {r['result']}",f"- expected: {', '.join(r['expected']) or 'none'}",f"- detected: {', '.join(r.get('detected',[])) or 'none'}",f"- missed: {', '.join(r.get('missed',[])) or 'none'}",f"- false positives: {r.get('false_positives',0)}",f"- elapsed_seconds: {r.get('elapsed_seconds')}",'']
    (out/'benchmark.md').write_text('\n'.join(lines),encoding='utf-8');print(json.dumps(summary,indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
