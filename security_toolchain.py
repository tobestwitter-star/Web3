"""Bounded adapters for locally installed Web3 security tools."""
from __future__ import annotations
import json, os, re, shutil, subprocess
from pathlib import Path
TOOLS={'slither':{'binary':'slither','kind':'static','license':'AGPL-3.0-or-later','project':'crytic/slither'},'aderyn':{'binary':'aderyn','kind':'static','license':'GPL-3.0','project':'Cyfrin/aderyn'},'forge':{'binary':'forge','kind':'test-fuzz','license':'Apache-2.0 OR MIT','project':'foundry-rs/foundry'},'echidna':{'binary':'echidna-test','kind':'property-fuzz','license':'AGPL-3.0','project':'crytic/echidna'},'medusa':{'binary':'medusa','kind':'coverage-guided-fuzz','license':'AGPL-3.0','project':'crytic/medusa'},'wake':{'binary':'wake','kind':'static-fuzz-framework','license':'ISC','project':'Ackee-Blockchain/wake'},'halmos':{'binary':'halmos','kind':'symbolic-testing','license':'AGPL-3.0','project':'a16z/halmos'},'ityfuzz':{'binary':'ityfuzz','kind':'hybrid-fuzz','license':'MIT','project':'ityfuzz/ityfuzz'},'osv-scanner':{'binary':'osv-scanner','kind':'dependency-scan','license':'Apache-2.0','project':'google/osv-scanner'},'gitleaks':{'binary':'gitleaks','kind':'secret-scan','license':'MIT','project':'gitleaks/gitleaks'}}
STATUS='UNVERIFIED — HUMAN REVIEW REQUIRED'
class SecurityToolchain:
 def inventory(self):return [{**{'name':n,'available':bool((p:=shutil.which(m['binary']))),'binary':p},**m} for n,m in TOOLS.items()]
 def detect_build(self,source_dir):
  root=Path(source_dir);hits=[];markers={'foundry':['foundry.toml'],'hardhat':['hardhat.config.js','hardhat.config.ts','hardhat.config.cjs','hardhat.config.mjs'],'brownie':['brownie-config.yaml','brownie-config.yml','brownie-config.py'],'truffle':['truffle-config.js','truffle-config.ts','truffle.js'],'ape':['ape-config.yaml','ape-config.yml']}
  if not root.is_dir():return {'primary':None,'detected':[],'error':'source directory does not exist'}
  for system,files in markers.items():
   ev=[f for f in files if (root/f).exists()]
   if ev:hits.append({'system':system,'evidence':ev})
  pkg=root/'package.json'
  if pkg.exists():
   try:
    d=json.loads(pkg.read_text());deps={**d.get('dependencies',{}),**d.get('devDependencies',{})}
    for dep,sys in [('hardhat','hardhat'),('truffle','truffle')]:
     if dep in deps and not any(x['system']==sys for x in hits):hits.append({'system':sys,'evidence':['package.json']})
   except (OSError,ValueError):pass
  if not hits and list(root.rglob('*.sol')):hits=[{'system':'solidity-generic','evidence':['*.sol']}]
  return {'primary':hits[0]['system'] if hits else None,'detected':hits,'solidity_files':len(list(root.rglob('*.sol')))}
 def _run(self,cmd,cwd,timeout):
  if not os.path.isdir(cwd):return {'ok':False,'error':'source directory does not exist'}
  try:
   p=subprocess.run(cmd,cwd=cwd,text=True,capture_output=True,timeout=max(1,min(timeout,300)));return {'ok':p.returncode==0,'returncode':p.returncode,'stdout':p.stdout[-30000:],'stderr':p.stderr[-15000:]}
  except FileNotFoundError:return {'ok':False,'error':f'tool not installed: {cmd[0]}'}
  except subprocess.TimeoutExpired:return {'ok':False,'error':'tool timed out'}
 def _json(self,text):
  try:return json.loads(text)
  except Exception:return None
 def parse_result(self,name,result):
  out=result.get('stdout','');obj=self._json(out);findings=[]
  if name=='slither' and isinstance(obj,dict):
   for d in obj.get('results',{}).get('detectors',[]):findings.append({'title':d.get('check','Slither detector'),'description':d.get('description',''),'severity':str(d.get('impact','medium')).lower(),'confidence':{'high':.85,'medium':.65,'low':.45}.get(str(d.get('confidence','')).lower(),.5),'evidence':d.get('elements',[])})
  elif name=='aderyn' and isinstance(obj,dict):
   for key in ('high_issues','medium_issues','low_issues'):
    for d in obj.get(key,[]) if isinstance(obj.get(key),list) else []:findings.append({'title':d.get('title','Aderyn issue'),'description':d.get('description',''),'severity':key.replace('_issues',''),'confidence':.6,'evidence':d})
  elif isinstance(obj,dict):
   for key in ('findings','issues','results'):
    vals=obj.get(key,[])
    for d in vals if isinstance(vals,list) else []:
     if isinstance(d,dict):findings.append({'title':d.get('title') or d.get('name') or name,'description':d.get('description') or d.get('message',''),'severity':str(d.get('severity','medium')).lower(),'confidence':.55,'evidence':d})
  return findings
 def _bounded_forge(self,source_dir,timeout):
  if not shutil.which('forge'):return {'ok':False,'skipped':True,'error':'forge not installed'}
  return self._run(['forge','test','--json','-vvv'],source_dir,timeout)
 def run_symbolic(self,source_dir,timeout=180,functions=None):
  if not shutil.which('halmos'):return {'tool':'halmos','status':'skipped','available':False,'error':'halmos not installed','findings':[],'evidence_level':'not_executed','confirmed_vulnerability':False,'review_status':STATUS}
  cmd=['halmos'];
  if functions:
   for fn in functions[:20]:cmd.extend(['--function',str(fn)])
  r=self._run(cmd,source_dir,timeout);text=(r.get('stdout','')+'\n'+r.get('stderr',''))
  counterexamples=re.findall(r'(?:Counterexample|counterexample):\s*([^\n]+)',text);failures=re.findall(r'^\s*\[(?:FAIL|FAILED)\][^\n]*|^\s*(?:FAIL|FAILED):[^\n]*',text,re.I|re.M)
  return {'tool':'halmos','status':'executed','result':r,'counterexamples':counterexamples[:20],'assertion_failures':failures[:20],'evidence_level':'symbolic_counterexample' if counterexamples else ('symbolic_assertion_failure' if failures else 'no_symbolic_failure_observed'),'confirmed_vulnerability':False,'review_status':STATUS}
 def run_invariants(self,source_dir,timeout=180):
  if not shutil.which('forge'):return {'tool':'forge-invariant','status':'skipped','error':'forge not installed','evidence_level':'not_executed','review_status':STATUS}
  r=self._run(['forge','test','--match-test','invariant_','--json','-vvv'],source_dir,timeout);text=r.get('stdout','')+'\n'+r.get('stderr','');obj=self._json(r.get('stdout',''));failed=False;failure_records=[]
  if isinstance(obj,dict):
   blob=json.dumps(obj).lower();failed=any(x in blob for x in ('"status":"failure"','"status":"failed"','"success":false','"result":"failure"'))
  if not failed:failed=bool(re.search(r'^\s*\[(?:FAIL|FAILED)\][^\n]*|^\s*(?:FAIL|FAILED):[^\n]*',text,re.I|re.M))
  if failed:failure_records=re.findall(r'^\s*\[(?:FAIL|FAILED)\][^\n]*|^\s*(?:FAIL|FAILED):[^\n]*',text,re.I|re.M)[:20]
  return {'tool':'forge-invariant','status':'executed','result':r,'invariant_failure_observed':failed,'failure_records':failure_records,'evidence_level':'invariant_failure' if failed else 'no_invariant_failure_observed','confirmed_vulnerability':False,'review_status':STATUS}
 def upgrade_surface(self,source_dir):
  root=Path(source_dir);signals=[];patterns={'delegatecall':r'\bdelegatecall\s*\(','proxy':r'(?:TransparentUpgradeableProxy|UUPS|ERC1967|upgradeTo(?:AndCall)?)','initializer':r'\b(?:initializer|reinitializer)\b','implementation_slot':r'(?:_IMPLEMENTATION_SLOT|IMPLEMENTATION_SLOT|proxiableUUID)','selfdestruct':r'\bselfdestruct\s*\('}
  for p in root.rglob('*.sol'):
   if any(x in p.parts for x in ('lib','node_modules','.git','out')):continue
   try:text=p.read_text(encoding='utf-8',errors='replace')
   except OSError:continue
   for kind,pat in patterns.items():
    for m in list(re.finditer(pat,text,re.I))[:20]:signals.append({'kind':kind,'file':str(p.relative_to(root)),'line':text[:m.start()].count('\n')+1,'evidence':text[max(0,m.start()-100):m.end()+180]})
  return {'signals':signals,'risk_classes':sorted({s['kind'] for s in signals}),'status':STATUS}
 def generate_and_validate(self,source_dir,findings,authorization_confirmed=False,timeout=180):
  if not authorization_confirmed:return {'status':'blocked','reason':'authorization_required','candidates':[]}
  from exploit_harness import HarnessGenerator,HarnessRunner
  from evidence_classifier import EvidenceClassifier
  gen=HarnessGenerator(source_dir);runner=HarnessRunner();classifier=EvidenceClassifier();candidates=[]
  for finding in (findings or [])[:10]:
   if float(finding.get('priority_score',finding.get('priority',0))) < 45: continue
   authorized_finding={**finding,'authorized':True}
   generated=gen.generate(authorized_finding,['foundry','echidna','medusa']);execution=[]
   for h in generated.get('harnesses',[]):
    if h.get('framework')=='foundry' and h.get('status')=='generated':
     ex=runner.run_foundry(source_dir,h['test_path'],timeout);ex['evidence']=classifier.classify(ex,h);execution.append(ex)
   candidates.append({'finding_id':finding.get('id'),'title':finding.get('title'),'generated':generated,'execution':execution,'status':STATUS})
  return {'status':'candidate_validation_complete','candidates':candidates,'review_status':STATUS,'note':'A failing generated test is evidence only. A candidate is not treated as reproduced unless the harness contains an explicit security assertion and the assertion fails.'}
 def fuzz(self,source_dir,authorization_confirmed=False,framework='auto',timeout=180,findings=None):
  if not authorization_confirmed:return {'status':'blocked','reason':'authorization_required','results':[]}
  build=self.detect_build(source_dir);chosen=framework if framework!='auto' else build.get('primary');generated=self.generate_and_validate(source_dir,findings,True,min(timeout,180)) if findings else {'status':'not_run','candidates':[]}
  if chosen in ('foundry','hardhat','solidity-generic') or chosen is None:return {'status':'bounded_local_validation','framework':'foundry','build':build,'results':[self._bounded_forge(source_dir,min(timeout,180))],'generated_candidates':generated,'destructive_live_testing':False}
  return {'status':'bounded_local_validation','framework':chosen,'build':build,'results':[],'generated_candidates':generated,'destructive_live_testing':False}
 def analyze(self,source_dir,tools=None,timeout=120):
  requested=tools or ['slither','osv-scanner','gitleaks'];build=self.detect_build(source_dir);results=[]
  for name in requested:
   meta=TOOLS.get(name)
   if not meta:results.append({'name':name,'ok':False,'error':'unsupported tool'});continue
   if not shutil.which(meta['binary']):results.append({'name':name,'skipped':True,'error':'not installed',**meta});continue
   cmd={'slither':['slither','.','--json','-'],'aderyn':['aderyn','--output','-','.'],'wake':['wake','detect'],'forge':['forge','test','--json'],'medusa':['medusa','fuzz','--help'],'echidna':['echidna-test','--help'],'halmos':['halmos'],'ityfuzz':['ityfuzz'],'osv-scanner':['osv-scanner','scan','--format','json','--recursive','.'],'gitleaks':['gitleaks','detect','--no-banner','--report-format','json','--report-path','-']}[name];r=self._run(cmd,source_dir,timeout);results.append({'name':name,**meta,'result':r,'findings':self.parse_result(name,r)})
  return {'authorized_local_analysis_only':True,'build':build,'results':results,'upgrade_surface':self.upgrade_surface(source_dir)}
