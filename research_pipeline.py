"""Authorized target acquisition, build-aware research and finding correlation."""
from __future__ import annotations
import hashlib,os,re,subprocess
from dataclasses import dataclass,asdict
from pathlib import Path
from typing import Any,Dict,List
from urllib.parse import urlparse
from advanced_web3_analyzer import AdvancedWeb3Analyzer
from security_toolchain import SecurityToolchain
from target_resolution import ScopeResolver,BuildDetector,TargetMap
from protocol_research import ProtocolMapper,BusinessLogicEngine,FindingPrioritizer,AttackPathEngine
from historical_intelligence import HistoricalIntelligence
from economic_analysis import EconomicAnalyzer
STATUS='UNVERIFIED — HUMAN REVIEW REQUIRED'
@dataclass
class Target:
 name:str;source_url:str;kind:str='repository';branch:str='';authorized:bool=False;scope_evidence:str='';addresses:List[str]=None;contracts:List[str]=None;assets:List[str]=None
 def to_dict(self):
  d=asdict(self)
  for k in ('addresses','contracts','assets'):d[k]=d[k] or []
  return d
class TargetAcquirer:
 GIT_RE=re.compile(r'https?://(?:www\.)?github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?(?:/tree/[^\s#]+)?');ADDRESS_RE=re.compile(r'\b0x[a-fA-F0-9]{40}\b')
 def extract_targets(self,opportunity,public_text=''):
  scope=ScopeResolver().resolve(opportunity,public_text);targets=[]
  for repo in scope['repositories']:targets.append(Target(opportunity.get('name','target'),repo,authorized=False,scope_evidence=public_text,addresses=scope['contract_addresses'],assets=scope['assets']))
  for addr in scope['contract_addresses']:targets.append(Target(opportunity.get('name','target'),'',kind='evm_contract',authorized=False,scope_evidence=public_text,addresses=[addr],assets=scope['assets']))
  return targets
 def clone_public_repo(self,target,workspace,authorization_confirmed=False):
  if not authorization_confirmed or not target.authorized:return {'ok':False,'blocked':'authorization_required','reason':'Explicit scope confirmation is required.'}
  if urlparse(target.source_url).netloc.lower()!='github.com':return {'ok':False,'error':'only public GitHub repositories are supported'}
  Path(workspace).mkdir(parents=True,exist_ok=True);dest=os.path.join(workspace,hashlib.sha256(target.source_url.encode()).hexdigest()[:12])
  if os.path.isdir(dest):return {'ok':True,'path':dest,'cached':True}
  try:p=subprocess.run(['git','clone','--depth','1',target.source_url,dest],capture_output=True,text=True,timeout=180);return {'ok':p.returncode==0,'path':dest if p.returncode==0 else None,'stdout':p.stdout[-4000:],'stderr':p.stderr[-6000:]}
  except (FileNotFoundError,subprocess.TimeoutExpired) as e:return {'ok':False,'error':str(e)}
class FindingCorrelator:
 SEVERITY={'critical':4,'high':3,'medium':2,'low':1,'informational':0};STOP={'the','and','with','risk','potential','attack','vulnerability','issue','complex','broken','advanced','business','logic'}
 TOOL_OBSERVATION_ONLY={'solc-version','naming-convention','immutable-states','constable-states','timestamp','missing-zero-check','unused-return','uninitialized-state','low-level-calls','locked-ether','reentrancy-no-eth'}
 def normalize(self,f,engine):
  text=' '.join(str(f.get(k,'')) for k in ('title','vulnerability','description','message','check'));loc=str(f.get('location') or f.get('path') or f.get('source') or '');sev=str(f.get('severity') or 'medium').lower();category=str(f.get('category') or '').lower();tokens=set(re.findall(r'[a-z0-9]{4,}',text.lower()))-self.STOP;raw=f.get('evidence',[]);evidence=raw if isinstance(raw,list) else [raw]
  return {'id':f.get('id') or hashlib.sha256((text+'|'+loc).encode()).hexdigest()[:16],'engine':engine,'title':f.get('title') or f.get('vulnerability') or f.get('check') or engine,'description':text[:4000],'location':loc,'severity':sev,'category':category,'confidence':float(f.get('confidence',.45) or .45),'evidence':evidence,'tokens':tokens,'fingerprint':hashlib.sha256((re.sub(r'\s+',' ',text.lower())+'|'+loc.lower()).encode()).hexdigest()}
 def _key(self,f):
  loc=re.sub(r'[^a-z0-9]',' ',f.get('location','').lower());return (f.get('category') or '',set(re.findall(r'[a-z0-9]{4,}',loc)))
 def _same_issue(self,a,b):
  if a['fingerprint']==b['fingerprint']:return True
  la,lb=self._key(a),self._key(b);loc_overlap=bool(la[1]&lb[1]) if la[1] and lb[1] else False;title_overlap=len(a['tokens']&b['tokens'])/max(1,len(a['tokens']|b['tokens']));category_match=bool(la[0] and la[0]==lb[0]);return (loc_overlap and title_overlap>=.18) or (category_match and title_overlap>=.28)
 def correlate(self,groups):
  merged=[]
  for g in groups:
   engine=g.get('engine','unknown')
   for raw in g.get('findings',[]):
    check=str(raw.get('check') or raw.get('name') or raw.get('title') or raw.get('vulnerability') or '').strip().lower()
    if engine!='existing_analyzer' and check in self.TOOL_OBSERVATION_ONLY: continue
    f=self.normalize(raw,engine);match=next((m for m in merged if self._same_issue(m,f)),None)
    if not match:merged.append({**f,'engines':[f['engine']],'occurrences':1,'cross_tool_confidence':f['confidence'],'duplicate_classification':'no useful match'})
    else:
     match['occurrences']+=1
     if f['engine'] not in match['engines']:match['engines'].append(f['engine'])
     match['cross_tool_confidence']=min(1,max(match['cross_tool_confidence'],f['confidence'])+.12);match['evidence'].extend(f['evidence']);match['duplicate_classification']='related multi-engine finding'
     if self.SEVERITY.get(f['severity'],2)>self.SEVERITY.get(match['severity'],2):match['severity']=f['severity']
  for f in merged:
   f['validated_by_multiple_tools']=len(f['engines'])>=2;f['status']=STATUS;f['priority']=round(self.SEVERITY.get(f['severity'],2)*25+min(25,f['cross_tool_confidence']*25)+(10 if f['validated_by_multiple_tools'] else 0),2);f.pop('tokens',None)
  return sorted(merged,key=lambda x:x['priority'],reverse=True)
class ResearchPipeline:
 def __init__(self):self.acquirer=TargetAcquirer();self.tools=SecurityToolchain();self.correlator=FindingCorrelator();self.scope=ScopeResolver();self.build=BuildDetector();self.mapper=ProtocolMapper();self.paths=AttackPathEngine();self.logic=BusinessLogicEngine();self.prioritizer=FindingPrioritizer();self.history=HistoricalIntelligence();self.economics=EconomicAnalyzer()
 def plan(self,opportunity,public_evidence=''):
  scope=self.scope.resolve(opportunity,public_evidence);return {'opportunity':opportunity,'scope':scope,'target_map':TargetMap().build(scope,{'detected':[],'primary':None}),'targets':[t.to_dict() for t in self.acquirer.extract_targets(opportunity,public_evidence)],'tools':self.tools.inventory(),'authorization_required':True,'active_testing_allowed':bool(opportunity.get('authorization_confirmed'))}
 def analyze_local(self,source_dir,protocol_name,source_code=None,authorization_confirmed=False,tools=None,opportunity=None):
  if not authorization_confirmed:return {'status':'blocked','reason':'Explicit authorization confirmation is required before analysis/testing.','findings':[]}
  if not Path(source_dir).is_dir():return {'status':'error','reason':'source directory does not exist','findings':[]}
  build=self.build.detect(source_dir);protocol_map=self.mapper.map(source_dir);attack_paths=self.paths.paths(protocol_map);hypotheses=self.logic.hypotheses(source_dir,protocol_map);groups=[]
  if source_code:
   try:
    fs=AdvancedWeb3Analyzer().analyze_protocol(source_code,protocol_name);lines=source_code.splitlines()
    def function_for_location(location):
     mm=re.search(r'line\s+(\d+)',str(location or ''),re.I);line=int(mm.group(1)) if mm else 1;lo=max(1,line-12);hi=min(len(lines),line+12);current=''
     for text in lines[lo-1:hi]:
      fm=re.search(r'\bfunction\s+(\w+)\s*\(',text)
      if fm:current=fm.group(1)
     return current
    groups.append({'engine':'existing_analyzer','findings':[{'id':f.id,'title':f.vulnerability_type,'severity':f.severity,'description':f.description,'location':f.location,'confidence':f.confidence,'evidence':[f.proof_of_concept],'category':f.category,'contract':protocol_name,'function':function_for_location(f.location)} for f in fs]})
   except Exception as e:groups.append({'engine':'existing_analyzer','findings':[],'error':str(e)})
  tr=self.tools.analyze(source_dir,tools or ['slither','aderyn','wake'],120)
  for r in tr.get('results',[]):groups.append({'engine':r.get('name','tool'),'findings':r.get('findings',[])})
  correlated=self.correlator.correlate(groups)
  for h in hypotheses:
   h['independent_signals']=1;h['reproducibility']=0.0;h['economic_impact_score']=.65 if h['category'] in ('asset_flow','accounting','oracle','privilege') else .4;h['attacker_privilege']='user';h['economic_analysis']=self.economics.analyze(h);h['status']=STATUS;h['kind']='exploratory_hypothesis'
  combined=correlated
  for f in combined:
   f['attack_paths']=[p for p in attack_paths if p.get('entry_point','')==f'{f.get("contract","")}.{f.get("function","")}' or p.get('entry_point','').split('.')[-1]==str(f.get('function',''))][:3] or (attack_paths[:2] if attack_paths else []);f['economic_analysis']=self.economics.analyze(f);f['status']=STATUS
  ranked=self.prioritizer.rank(combined,opportunity);candidate_validation=self.tools.generate_and_validate(source_dir,ranked[:10],True,180);symbolic=self.tools.run_symbolic(source_dir,180);invariants=self.tools.run_invariants(source_dir,180);upgrade_surface=self.tools.upgrade_surface(source_dir)
  for c in candidate_validation.get('candidates',[]):
   for ex in c.get('execution',[]):
    if ex.get('status')=='executed':
     for f in ranked:
      if f.get('id')==c.get('finding_id'):
       ev=ex.get('evidence') or {};f['execution_evidence']=ev or {'returncode':ex.get('returncode'),'candidate_failed':ex.get('candidate_failed'),'stdout':ex.get('stdout','')[-12000:],'stderr':ex.get('stderr','')[-8000:]};f['reproducibility']=float(ev.get('reproducibility_score',0.0));f['status']=STATUS
  ranked=self.prioritizer.rank(ranked,opportunity)
  return {'status':'analysis_complete','authorization_confirmed':True,'build':build,'protocol_map':protocol_map,'attack_paths':attack_paths,'business_logic_hypotheses':hypotheses[:100],'tool_results':tr,'symbolic_validation':symbolic,'invariant_validation':invariants,'upgrade_surface':upgrade_surface,'correlated_findings':ranked,'exploit_test_candidates':candidate_validation,'historical_search_leads':[self.history.search_urls(f.get('title',''),f.get('category','')) for f in ranked[:10]],'review_status':STATUS}
