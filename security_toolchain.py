"""Bounded adapters for locally installed Web3 security tools."""
from __future__ import annotations
import json, os, re, shutil, subprocess
from pathlib import Path
from typing import Any
TOOLS={'slither':{'binary':'slither','kind':'static','license':'AGPL-3.0-or-later','project':'crytic/slither'},'aderyn':{'binary':'aderyn','kind':'static','license':'GPL-3.0','project':'Cyfrin/aderyn'},'forge':{'binary':'forge','kind':'test-fuzz','license':'Apache-2.0 OR MIT','project':'foundry-rs/foundry'},'echidna':{'binary':'echidna-test','kind':'property-fuzz','license':'AGPL-3.0','project':'crytic/echidna'},'medusa':{'binary':'medusa','kind':'coverage-guided-fuzz','license':'AGPL-3.0','project':'crytic/medusa'},'wake':{'binary':'wake','kind':'static-fuzz-framework','license':'ISC','project':'Ackee-Blockchain/wake'}}
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
 def generate_and_validate(self,source_dir,findings,authorization_confirmed=False,timeout=180):
  if not authorization_confirmed:return {'status':'blocked','reason':'authorization_required','candidates':[]}
  from exploit_harness import HarnessGenerator,HarnessRunner
  gen=HarnessGenerator(source_dir);runner=HarnessRunner();candidates=[]
  for finding in (findings or [])[:10]:
   if float(finding.get('priority_score',0)) < 45: continue
   generated=gen.generate(finding,['foundry','echidna','medusa']);execution=[]
   for h in generated.get('harnesses',[]):
    if h.get('framework')=='foundry' and h.get('status')=='generated':
     execution.append(runner.run_foundry(source_dir,h['test_path'],timeout))
   # Execution is evidence only; no result is promoted to confirmed automatically.
   candidates.append({'finding_id':finding.get('id'),'title':finding.get('title'),'generated':generated,'execution':execution,'status':'UNVERIFIED — HUMAN REVIEW REQUIRED'})
  return {'status':'candidate_validation_complete','candidates':candidates,'review_status':'UNVERIFIED — HUMAN REVIEW REQUIRED','note':'A failing generated test is evidence for human review, not automatic vulnerability confirmation.'}
 def fuzz(self,source_dir,authorization_confirmed=False,framework='auto',timeout=180,findings=None):
  if not authorization_confirmed:return {'status':'blocked','reason':'authorization_required','results':[]}
  build=self.detect_build(source_dir);chosen=framework if framework!='auto' else build.get('primary')
  if findings:
   generated=self.generate_and_validate(source_dir,findings,True,min(timeout,180))
  else: generated={'status':'not_run','candidates':[]}
  if chosen in ('foundry','hardhat','solidity-generic') or chosen is None:return {'status':'bounded_local_validation','framework':'foundry','build':build,'results':[self._bounded_forge(source_dir,min(timeout,180))],'generated_candidates':generated,'destructive_live_testing':False}
  if chosen in ('echidna','medusa'):
   binary='echidna-test' if chosen=='echidna' else 'medusa'
   if not shutil.which(binary):return {'status':'bounded_local_validation','framework':chosen,'build':build,'results':[{'ok':False,'skipped':True,'error':f'{binary} not installed'}],'generated_candidates':generated,'destructive_live_testing':False}
   cmd=[binary,'--help'] if chosen=='echidna' else [binary,'fuzz','--help'];return {'status':'bounded_local_validation','framework':chosen,'build':build,'results':[self._run(cmd,source_dir,min(timeout,180))],'generated_candidates':generated,'destructive_live_testing':False}
  return {'status':'bounded_local_validation','framework':chosen,'build':build,'results':[],'generated_candidates':generated,'destructive_live_testing':False}
 def analyze(self,source_dir,tools=None,timeout=120):
  requested=tools or ['slither','aderyn','wake'];build=self.detect_build(source_dir);results=[]
  for name in requested:
   meta=TOOLS.get(name)
   if not meta:results.append({'name':name,'ok':False,'error':'unsupported tool'});continue
   if not shutil.which(meta['binary']):results.append({'name':name,'skipped':True,'error':'not installed',**meta});continue
   cmd={'slither':['slither','.','--json','-'],'aderyn':['aderyn','--output','-','.'],'wake':['wake','detect'],'forge':['forge','test','--json'],'medusa':['medusa','fuzz','--help'],'echidna':['echidna-test','--help']}[name]
   r=self._run(cmd,source_dir,timeout);results.append({'name':name,**meta,'result':r,'findings':self.parse_result(name,r)})
  return {'authorized_local_analysis_only':True,'build':build,'results':results}
