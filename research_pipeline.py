"""Authorized target acquisition, build-aware research and finding correlation."""
from __future__ import annotations
import hashlib, os, re, subprocess
from dataclasses import dataclass,asdict
from pathlib import Path
from typing import Any,Dict,Iterable,List,Optional
from urllib.parse import urlparse
from advanced_web3_analyzer import AdvancedWeb3Analyzer
from security_toolchain import SecurityToolchain
from target_resolution import ScopeResolver,BuildDetector,TargetMap
@dataclass
class Target:
 name:str; source_url:str; kind:str='repository'; branch:str=''; authorized:bool=False; scope_evidence:str=''; addresses:List[str]=None; contracts:List[str]=None; assets:List[str]=None
 def to_dict(self):
  d=asdict(self)
  for k in ('addresses','contracts','assets'):d[k]=d[k] or []
  return d
class TargetAcquirer:
 GIT_RE=re.compile(r'https?://(?:www\.)?github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?(?:/tree/[^\s#]+)?');ADDRESS_RE=re.compile(r'\b0x[a-fA-F0-9]{40}\b')
 def extract_targets(self,opportunity:Dict[str,Any],public_text=''):
  scope=ScopeResolver().resolve(opportunity,public_text);targets=[]
  for repo in scope['repositories']:targets.append(Target(opportunity.get('name','target'),repo,authorized=False,scope_evidence=public_text,addresses=scope['contract_addresses'],assets=scope['assets']))
  for addr in scope['contract_addresses']:
   targets.append(Target(opportunity.get('name','target'),'',kind='evm_contract',authorized=False,scope_evidence=public_text,addresses=[addr],assets=scope['assets']))
  return targets
 def clone_public_repo(self,target,workspace,authorization_confirmed=False):
  if not authorization_confirmed or not target.authorized:return {'ok':False,'blocked':'authorization_required','reason':'Explicit scope confirmation is required.'}
  if urlparse(target.source_url).netloc.lower()!='github.com':return {'ok':False,'error':'only public GitHub repositories are supported'}
  Path(workspace).mkdir(parents=True,exist_ok=True);dest=os.path.join(workspace,hashlib.sha256(target.source_url.encode()).hexdigest()[:12])
  if os.path.isdir(dest):return {'ok':True,'path':dest,'cached':True}
  try:
   p=subprocess.run(['git','clone','--depth','1',target.source_url,dest],capture_output=True,text=True,timeout=180);return {'ok':p.returncode==0,'path':dest if p.returncode==0 else None,'stdout':p.stdout[-4000:],'stderr':p.stderr[-6000:]}
  except (FileNotFoundError,subprocess.TimeoutExpired) as e:return {'ok':False,'error':str(e)}
class FindingCorrelator:
 SEVERITY={'critical':4,'high':3,'medium':2,'low':1,'informational':0}
 def normalize(self,f,engine):
  text=' '.join(str(f.get(k,'')) for k in ('title','vulnerability','description','message','check'));loc=str(f.get('location') or f.get('path') or f.get('source') or '')
  sev=str(f.get('severity') or 'medium').lower();return {'engine':engine,'title':f.get('title') or f.get('vulnerability') or f.get('check') or engine,'description':text[:4000],'location':loc,'severity':sev,'confidence':float(f.get('confidence',.45) or .45),'evidence':f.get('evidence',[]),'fingerprint':hashlib.sha256((re.sub(r'\s+',' ',text.lower())+'|'+loc.lower()).encode()).hexdigest()}
 def correlate(self,groups):
  merged={}
  for g in groups:
   for raw in g.get('findings',[]):
    f=self.normalize(raw,g.get('engine','unknown'));key=f['fingerprint'][:20]
    if key not in merged:merged[key]={**f,'engines':[f['engine']],'occurrences':1,'cross_tool_confidence':f['confidence']}
    else:
     m=merged[key];m['occurrences']+=1
     if f['engine'] not in m['engines']:m['engines'].append(f['engine'])
     m['cross_tool_confidence']=min(1,max(m['cross_tool_confidence'],f['confidence'])+.12);m['evidence']=m['evidence']+[f['evidence']]
     if self.SEVERITY.get(f['severity'],2)>self.SEVERITY.get(m['severity'],2):m['severity']=f['severity']
  for f in merged.values():
   f['validated_by_multiple_tools']=len(f['engines'])>=2;f['status']='UNVERIFIED — HUMAN REVIEW REQUIRED';f['priority']=round(self.SEVERITY.get(f['severity'],2)*25+min(25,f['cross_tool_confidence']*25)+(10 if f['validated_by_multiple_tools'] else 0),2)
  return sorted(merged.values(),key=lambda x:x['priority'],reverse=True)
class ResearchPipeline:
 def __init__(self):self.acquirer=TargetAcquirer();self.tools=SecurityToolchain();self.correlator=FindingCorrelator();self.scope=ScopeResolver();self.build=BuildDetector()
 def plan(self,opportunity,public_evidence=''):
  scope=self.scope.resolve(opportunity,public_evidence);available=self.tools.inventory();return {'opportunity':opportunity,'scope':scope,'target_map':TargetMap().build(scope,{'detected':[],'primary':None}),'targets':[t.to_dict() for t in self.acquirer.extract_targets(opportunity,public_evidence)],'tools':available,'authorization_required':True,'active_testing_allowed':bool(opportunity.get('authorization_confirmed'))}
 def analyze_local(self,source_dir,protocol_name,source_code=None,authorization_confirmed=False,tools=None):
  if not authorization_confirmed:return {'status':'blocked','reason':'Explicit authorization confirmation is required before analysis/testing.','findings':[]}
  build=self.build.detect(source_dir);groups=[]
  if source_code:
   try:
    fs=AdvancedWeb3Analyzer().analyze_protocol(source_code,protocol_name);groups.append({'engine':'existing_analyzer','findings':[{'title':f.vulnerability_type,'severity':f.severity,'description':f.description,'location':f.location,'confidence':f.confidence,'evidence':f.proof_of_concept} for f in fs]})
   except Exception as e:groups.append({'engine':'existing_analyzer','findings':[],'error':str(e)})
  chosen=tools or ['slither','aderyn','wake']
  tr=self.tools.analyze(source_dir,chosen,120)
  for r in tr.get('results',[]):groups.append({'engine':r.get('name','tool'),'findings':r.get('findings',[])})
  return {'status':'analysis_complete','authorization_confirmed':True,'build':build,'tool_results':tr,'correlated_findings':self.correlator.correlate(groups),'review_status':'UNVERIFIED — HUMAN REVIEW REQUIRED'}
