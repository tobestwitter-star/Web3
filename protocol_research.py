"""Offline-first protocol understanding and evidence-gated security reasoning."""
from __future__ import annotations
import hashlib,re
from pathlib import Path
from typing import Any,Dict,List
SOL_RE=re.compile(r'(?:abstract\s+)?contract\s+(\w+)(?:\s+is\s+([^\{]+))?',re.I)
FN_RE=re.compile(r'\bfunction\s+(\w+)\s*\(([^)]*)\)\s*([^\{;]*)',re.I)
CALL_RE=re.compile(r'\b([A-Za-z_]\w*)\s*\.\s*(call|delegatecall|staticcall|transfer|send)\s*(?:\{|\()',re.I)
ROLE_RE=re.compile(r'\b(?:only[A-Za-z0-9_]*|hasRole|grantRole|revokeRole|_authorizeUpgrade|owner|admin)\b',re.I)
ORACLE_RE=re.compile(r'\b(?:oracle|chainlink|latestAnswer|latestRoundData|getPrice|priceFeed|twap|spotPrice)\b',re.I)
UPGRADE_RE=re.compile(r'\b(?:upgradeTo|upgradeToAndCall|UUPS|TransparentUpgradeableProxy|ERC1967|initializer|reinitializer|delegatecall)\b',re.I)
VALUE_RE=re.compile(r'\b(?:transferFrom|safeTransferFrom|safeTransfer|transfer|mint|burn|deposit|withdraw|redeem|borrow|repay|liquidat|swap|claim|reward|fee)\w*\b',re.I)
class ProtocolMapper:
 def map(self,source_dir):
  root=Path(source_dir);contracts=[];functions=[];edges=[];files=[]
  if not root.is_dir():return {'error':'source directory does not exist','contracts':[],'functions':[],'attack_graph':{'nodes':[],'edges':[]}}
  all_names=[]
  for path in root.rglob('*.sol'):
   if any(part in {'lib','node_modules','.git','out'} for part in path.parts):continue
   try:text=path.read_text(encoding='utf-8',errors='replace')
   except OSError:continue
   rel=str(path.relative_to(root));files.append(rel)
   for m in SOL_RE.finditer(text):
    name=m.group(1);all_names.append(name);bases=(m.group(2) or '').strip();contracts.append({'name':name,'file':rel,'bases':[x.strip() for x in bases.split(',') if x.strip()],'external_calls':len(CALL_RE.findall(text)),'value_operations':len(VALUE_RE.findall(text)),'oracle_signals':len(ORACLE_RE.findall(text)),'upgrade_signals':len(UPGRADE_RE.findall(text)),'privilege_signals':len(ROLE_RE.findall(text))})
    for fn in FN_RE.finditer(text):
     functions.append({'contract':name,'name':fn.group(1),'file':rel,'line':text[:fn.start()].count('\n')+1,'signature':fn.group(2).strip(),'modifiers':fn.group(3).strip(),'external_call':bool(CALL_RE.search(text[fn.start():fn.start()+800])),'value_flow':bool(VALUE_RE.search(fn.group(1)+fn.group(2)+fn.group(3))) ,'oracle_dependency':bool(ORACLE_RE.search(text[fn.start():fn.start()+1200])),'privileged':bool(ROLE_RE.search(fn.group(3))),'payable':bool(re.search(r'\bpayable\b',fn.group(3),re.I))})
    for m in re.finditer(r'\b([A-Za-z_]\w*)\s*\(',text):
     if m.group(1) in all_names:edges.append({'from':rel,'to':m.group(1),'kind':'contract-reference'})
  nodes=[{'id':c['name'],'type':'contract','file':c['file']} for c in contracts]+[{'id':f"{f['contract']}.{f['name']}",'type':'function','file':f['file'],'line':f['line']} for f in functions]
  edges += [{'from':f['contract'],'to':f"{f['contract']}.{f['name']}",'kind':'defines'} for f in functions]
  return {'files':files,'contracts':contracts,'functions':functions,'attack_graph':{'nodes':nodes,'edges':edges},'architecture':{'contract_count':len(contracts),'function_count':len(functions),'external_call_count':sum(c['external_calls'] for c in contracts),'value_flow_contracts':sum(bool(c['value_operations']) for c in contracts),'oracle_contracts':sum(bool(c['oracle_signals']) for c in contracts),'upgradeable_contracts':sum(bool(c['upgrade_signals']) for c in contracts),'privileged_contracts':sum(bool(c['privilege_signals']) for c in contracts)}}
class AttackPathEngine:
 def paths(self,protocol_map,max_paths=30):
  fs=protocol_map.get('functions',[]);paths=[]
  for f in fs:
   risk=[]
   if f.get('value_flow'):risk.append('asset movement')
   if f.get('oracle_dependency'):risk.append('oracle input')
   if f.get('external_call'):risk.append('external callback')
   if f.get('privileged'):risk.append('privileged boundary')
   if risk:
    paths.append({'sequence':[{'contract':f['contract'],'function':f['name'],'file':f['file'],'line':f['line']}],'risk_signals':risk,'attacker_privilege':'role/admin' if f.get('privileged') else 'user','preconditions':['Function must be reachable under its declared visibility/modifiers.'],'state_changes':['Inspect storage writes and token movements in the function body.'],'assets_affected':'source-derived asset flow requires confirmation','expected_gain':'not quantified until a local reproduction supplies balances/prices','protocol_loss':'not quantified until a local reproduction supplies balances/prices','why_checks_fail':'hypothesis only; authorization and invariant checks must be reproduced','status':'UNVERIFIED — HUMAN REVIEW REQUIRED'})
  return paths[:max_paths]
class BusinessLogicEngine:
 PATTERNS=[('accounting','Broken accounting / balance conservation',r'(?:totalAssets|totalSupply|shares|debt|balance|reserve)[^\n]{0,160}(?:\+|-|\*|/|=)','Review conservation invariants and rounding around value-changing operations.'),('state_machine','State-machine transition risk',r'(?:state|status)\s*(?:=|\+=|-=)|enum\s+\w*State','Review every reachable transition and whether callers can skip required states.'),('privilege','Privilege-boundary risk',r'function\s+\w+[^\{]{0,180}\b(?:public|external)\b[^\{]{0,180}(?:owner|admin|role|upgrade|mint|burn)','Check whether every privileged state/value mutation has an explicit authorization invariant.'),('oracle','Oracle dependency risk',ORACLE_RE.pattern,'Check stale prices, source concentration, decimal normalization, and manipulation windows.'),('upgrade','Initialization/upgrade risk',UPGRADE_RE.pattern,'Check initializer reachability, implementation initialization, storage compatibility and upgrade authorization.'),('asset_flow','Unexpected asset-flow risk',VALUE_RE.pattern,'Trace token movement across contracts and verify caller-controlled recipient/amount constraints.'),('external_call','Cross-contract callback risk',CALL_RE.pattern,'Check reentrancy/callback ordering and state updates across contract boundaries.'),('precision','Precision/rounding risk',r'\b(?:10\*\*|1e\d+|/\s*\d+|mulDiv|round|decimals)\b','Check unit conversion, rounding direction and small/large-value boundaries.')]
 def hypotheses(self,source_dir,protocol_map):
  root=Path(source_dir);out=[]
  for path in root.rglob('*.sol'):
   if any(x in path.parts for x in ('lib','node_modules','.git','out')):continue
   try:text=path.read_text(encoding='utf-8',errors='replace')
   except OSError:continue
   for category,title,pattern,question in self.PATTERNS:
    for m in list(re.finditer(pattern,text,re.I))[:12]:
     line=text[:m.start()].count('\n')+1;context=text[max(0,m.start()-240):min(len(text),m.end()+360)];score=self._score(category,context)
     out.append({'id':hashlib.sha256((category+str(path)+str(line)).encode()).hexdigest()[:16],'category':category,'title':title,'file':str(path.relative_to(root)),'line':line,'hypothesis':question,'evidence':[f'{path.relative_to(root)}:{line}',context[:800]],'severity_potential':'high' if score>=70 else 'medium','exploitability':round(score/100,2),'confidence':round(min(.85,score/100),2),'status':'UNVERIFIED — HUMAN REVIEW REQUIRED','validation_required':True})
  return sorted(out,key=lambda x:x['exploitability'],reverse=True)
 def _score(self,category,context):
  s=40;low=context.lower()
  if category in ('asset_flow','accounting'):s+=18
  if category in ('privilege','oracle','external_call'):s+=12
  if any(x in low for x in ('require','revert','onlyowner','onlyrole','nonreentrant')):s-=8
  if any(x in low for x in ('msg.sender','msg.value','transferfrom','delegatecall')):s+=8
  return max(10,min(95,s))
class FindingPrioritizer:
 def rank(self,findings,opportunity=None):
  bounty=float((opportunity or {}).get('max_bounty_usd') or 0);bounty_factor=min(1,bounty/25000)
  for f in findings:
   sev={'critical':1,'high':.8,'medium':.55,'low':.3}.get(str(f.get('severity') or f.get('severity_potential') or 'medium').lower(),.55);signals=min(1,float(f.get('independent_signals',1))/3);priv={'none':1,'user':.8,'role':.35,'admin':.2}.get(str(f.get('attacker_privilege','user')).lower(),.7)
   f['priority_score']=round(100*(.24*sev+.18*float(f.get('exploitability',.4))+.16*float(f.get('economic_impact_score',.4))+.14*float(f.get('confidence',.4))+.10*float(f.get('reproducibility',.2))+.08*signals+.06*bounty_factor+.04*priv),2);f['status']='UNVERIFIED — HUMAN REVIEW REQUIRED'
  return sorted(findings,key=lambda x:x['priority_score'],reverse=True)
