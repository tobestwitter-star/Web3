#!/usr/bin/env python3
"""Existing Web3 BugHunter analyzer, preserved as the core code-analysis engine.
Evidence-gated source analysis; all findings remain UNVERIFIED — HUMAN REVIEW REQUIRED.
"""
from flask import Flask
import anthropic, os, re
from dataclasses import dataclass
app=Flask(__name__)
client=anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY")) if os.environ.get("ANTHROPIC_API_KEY") else None
STATUS="UNVERIFIED — HUMAN REVIEW REQUIRED"
@dataclass
class Finding:
 id:str; vulnerability_type:str; severity:str; category:str; location:str; description:str; proof_of_concept:str; economic_impact:str; likelihood_score:float; bounty_estimate_low:int; bounty_estimate_high:int; confidence:float; requires_verification:bool; learning_value:str
class AdvancedWeb3Analyzer:
 def __init__(self): self.findings=[];self.protocol_knowledge={};self.exploit_patterns=[]
 def analyze_protocol(self,code,protocol_name,network="ethereum"):
  fs=self._specialized(code)+self._legacy_signals(code);out={}
  for f in fs:
   k=(f.category,f.location,f.vulnerability_type)
   if k not in out or f.confidence>out[k].confidence:out[k]=f
  self.findings=list(out.values());return self.findings
 def _finding(self,key,name,severity,category,code,pos,desc,evidence,impact="Source-derived impact requires local reproduction.",confidence=.72):
  return Finding(f"{key}_{len(self.findings)}",name,severity,category,f"Source evidence near line {self._line(code,pos)}",desc,evidence[:1600],impact,confidence,self._low(severity),self._high(severity,confidence),confidence,True,"Validate the complete attacker path and security invariant locally.")
 def _functions(self,code):
  out=[]
  for m in re.finditer(r'\bfunction\s+(\w+)\s*\(([^)]*)\)([^\{;]*)\{',code,re.I):
   depth=1;i=m.end()
   while i<len(code) and depth:
    if code[i]=='{':depth+=1
    elif code[i]=='}':depth-=1
    i+=1
   out.append((m,m.group(1),m.group(2),m.group(3),code[m.end():max(m.end(),i-1)]))
  return out
 def _has_auth(self,head,body):
  s=head+' '+body
  return bool(re.search(r'\b(?:onlyOwner|onlyRole|hasRole|_authorizeUpgrade|authorized|isOwner)\b',s,re.I) or re.search(r'\brequire\s*\([^;\n]{0,220}\b(?:msg\.sender|owner|admin|role)\b',s,re.I))
 def _write_pattern(self):return r'\b(?:balance|balances|shares|debt|state|status|owner|admin|total[A-Za-z]*|allowance|credits)\w*(?:\s*\[[^\]]+\])?\s*(?:=|\+=|-=|\*=)'
 def _state_write_after(self,body,pos):return bool(re.search(self._write_pattern(),body[pos:],re.I))
 def _sensitive_write(self,body):return bool(re.search(self._write_pattern(),body,re.I))
 def _specialized(self,code):
  fs=[];funcs=self._functions(code)
  for m,name,args,head,body in funcs:
   if not re.search(r'\becrecover\s*\(',body,re.I):continue
   action=bool(re.search(r'\b(?:claim|permit|execute|withdraw|mint|approve|transfer|setOwner|setAdmin)\w*\b',name,re.I)) or self._sensitive_write(body)
   freshness=bool(re.search(r'\b(?:nonce|used|usedHash|usedDigest|deadline|expiry|chainId|domainSeparator|DOMAIN_SEPARATOR|EIP712)\b',body,re.I))
   if action and not freshness:
    ev=body[:1800];fs += [self._finding('signature_replay','Replayable signature authorization path','high','signature',code,m.start(),'Signer recovery authorizes a security-sensitive state change, but no local nonce/consumed-digest/expiry/chain-domain binding is observed.',ev,'Potential unauthorized repeated execution; exact asset impact requires local reproduction.',.86),self._finding('replay','Missing signature replay protection','high','replay',code,m.start(),'A recovered-signature authorization appears reusable because freshness or one-time consumption is absent before the state mutation.',ev,'Potential repeated execution of an otherwise valid authorization.',.84)]
  for m,name,args,head,body in funcs:
   if not re.fullmatch(r'(?:initialize|init|reinitialize)',name,re.I):continue
   privileged=bool(re.search(r'\b(?:owner|admin|implementation|pendingOwner|upgrader)\b\s*=',body,re.I));guard=bool(re.search(r'\b(?:initializer|reinitializer|onlyInitializing|_disableInitializers)\b',head+' '+body,re.I) or re.search(r'\brequire\s*\([^;\n]{0,120}!\s*initialized\b',body,re.I) or re.search(r'\b(?:initialized|initializedFlag)\s*(?:==|!=)\s*(?:false|0)\b',body,re.I))
   if privileged and not guard:
    ev=body[:1500];fs += [self._finding('initialization','Unprotected initializer / initialization takeover','critical','initialization',code,m.start(),'An externally reachable initializer assigns privileged control state without an observed one-time initialization guard.',ev,'An attacker may establish ownership/admin state before legitimate initialization.',.92),self._finding('init_privilege','Initialization privilege escalation','critical','privilege',code,m.start(),'A public initializer can establish owner/admin state without an observed authorization or one-time guard.',ev,'Potential takeover of privileged protocol operations.',.9)]
    if re.search(r'\b(?:upgrade|implementation|upgrader)\b',code,re.I):fs.append(self._finding('init_upgrade','Initialization exposes upgrade privilege boundary','high','upgrade',code,m.start(),'Initialization controls an upgrade-relevant privilege without an observed initialization guard.',ev,'Potential unauthorized upgrade/control if initialization is reachable.',.88))
  for m,name,args,head,body in funcs:
   if re.search(r'\bnonReentrant\b',head,re.I) or re.search(r'\block(?:ed)?\s*=\s*true\b',head+' '+body,re.I):continue
   for call in re.finditer(r'\b\w+\s*\.\s*(?:call|send|transfer)\b',body,re.I):
    if self._state_write_after(body,call.end()):
     ev=body[:1800];fs += [self._finding('reentrancy','Reentrancy: external callback precedes state update','critical','reentrancy',code,m.start(),'An external call occurs before a relevant state write and no obvious reentrancy mutex is present. This is an attack-path candidate, not confirmation.',ev,'Potential repeated or inconsistent state/value movement; local attacker callback reproduction is required.',.88),self._finding('callback','Unsafe callback flow before accounting/state mutation','high','callback',code,m.start(),'An external call precedes finalization of sensitive accounting/state and may permit callback-controlled reentry.',ev,'Potential cross-function or callback reentrancy; impact requires local reproduction.',.82),self._finding('external_call','Security-sensitive external call ordering','high','external_call',code,m.start(),'A cross-contract call precedes a relevant state mutation in the same callable path.',ev,'Potential callback-controlled state manipulation; validate locally.',.78)];break
  sensitive=r'^(?:upgrade|upgradeTo|upgradeToAndCall|mintCredit|mintShares|mintTokens|burnFrom|pause|unpause|sweep|withdrawAll|transferOwnership|setOwner|setAdmin)$'
  for m,name,args,head,body in funcs:
   if not re.fullmatch(sensitive,name,re.I):continue
   if not (self._sensitive_write(body) or re.search(r'\b(?:transfer|call|delegatecall|selfdestruct)\b',body,re.I)):continue
   if self._has_auth(head,body):continue
   ev=body[:1600];fs += [self._finding('access_control','Sensitive operation lacks an observed authorization guard','high','access_control',code,m.start(),'A protocol-sensitive operation mutates privileged/value-bearing state without an observed owner, role, or authorization invariant.',ev,'Potential unauthorized privileged action; prove reachability and consequence locally.',.8),self._finding('privilege','Privilege escalation path','high','privilege',code,m.start(),'A caller appears able to reach a protocol-sensitive mutation without a visible authorization guard.',ev,'Potential unauthorized control/value movement.',.78)]
  for m,name,args,head,body in funcs:
   cb=re.search(r'\bonTokenReceived\s*\(|\bonERC\w+\s*\(|\btokensReceived\s*\(',body,re.I)
   if cb and self._state_write_after(body,cb.end()):
    ev=body[:1800];fs += [self._finding('callback_token','Token callback precedes balance accounting','high','callback',code,m.start(),'A receiver callback occurs before sender/recipient balances are finalized.',ev,'Potential callback reentrancy or inconsistent token accounting.',.86),self._finding('callback_asset','External callback asset-flow risk','high','external_call',code,m.start(),'A token transfer path invokes an external receiver before completing its accounting mutation.',ev,'Potential unauthorized repeated transfer or accounting inconsistency.',.82)]
  self._fallback_critical(code,fs);return fs
 def _fallback_critical(self,code,fs):
  def add(key,name,sev,cat,pos,desc,evidence,impact,conf):
   if not any(x.vulnerability_type==name and x.category==cat for x in fs):fs.append(self._finding(key,name,sev,cat,code,pos,desc,evidence,impact,conf))
  for cm in re.finditer(r'\b\w+\.call\s*\{[^}]*\}',code,re.I):
   end=code.find('function ',cm.end());window=code[cm.end():end if end>=0 else len(code)]
   if re.search(self._write_pattern(),window,re.I) and not re.search(r'\bnonReentrant\b',code[max(0,cm.start()-180):cm.start()],re.I):
    add('reentrancy_fallback','Reentrancy: external callback precedes state update','critical','reentrancy',cm.start(),'An external value call is followed by a sensitive indexed state write in the same source region without an observed reentrancy guard.',window[:1400],'Potential repeated withdrawal or inconsistent state; local callback reproduction is required.',.86);break
  for m in re.finditer(r'\bfunction\s+(mintCredit|mintShares|mintTokens|burnFrom|upgrade\w*|sweep|setOwner|setAdmin)\s*\(',code,re.I):
   end=code.find('function ',m.end());window=code[m.end():end if end>=0 else len(code)]
   if self._sensitive_write(window) and not self._has_auth(code[m.start():m.end()],window):
    add('access_control_fallback','Sensitive operation lacks an observed authorization guard','high','access_control',m.start(),'A protocol-sensitive operation mutates value-bearing/privileged state without a visible authorization check.',window[:1400],'Potential unauthorized privileged action; prove reachability locally.',.8);break
  for m in re.finditer(r'\bonTokenReceived\s*\(',code,re.I):
   end=code.find('function ',m.end());window=code[m.end():end if end>=0 else len(code)]
   if re.search(self._write_pattern(),window,re.I):add('callback_fallback','Token callback precedes balance accounting','high','callback',m.start(),'A receiver callback is followed by sensitive balance/accounting mutation without completion before the callback.',window[:1400],'Potential callback reentrancy or accounting inconsistency.',.84);break
 def _legacy_signals(self,code):
  specs=[('state_machine','State Machine Manipulation','critical','business_logic',[r'\b(?:state|status)\s*=']),('oracle','Oracle Manipulation / Price Attack','critical','oracle_attack',[r'\b(?:oracle|chainlink|latestAnswer|latestRoundData|getPrice|priceFeed|twap|spotPrice)\b']),('flash','Flash Loan Attack Vector','critical','flash_loan',[r'\b(?:flashLoan|flashSwap)\b']),('delegatecall','Unsafe delegatecall / upgrade surface','high','delegatecall',[r'\.(?:delegatecall|callcode)\s*\(']),('precision','Precision / rounding risk','medium','precision',[r'\b(?:mulDiv|decimals|round|1e\d+|10\s*\*\*|/\s*\d+)\b'])]
  fs=[]
  for key,name,sev,cat,pats in specs:
   for p in pats:
    m=re.search(p,code,re.I)
    if m:fs.append(self._finding(key,name,sev,cat,code,m.start(),'Source-level signal requiring an end-to-end attacker-path check.',code[max(0,m.start()-180):min(len(code),m.end()+500)],'Impact is not quantified until local reproduction establishes the security consequence.',.58))
  for m in re.finditer(r'\b(?:withdraw|redeem|transfer)\w*\s*\([^)]*\)\s*[^\{]*\{(?P<body>.*?)\}',code,re.I|re.S):
   b=m.group('body');payout=re.search(r'\b(?:transfer|send)\s*\([^;]*\b(?:amount|shares)\b[^;]*\+\s*1\b',b,re.I)
   if payout:fs.append(self._finding('accounting','Accounting conservation mismatch','high','accounting',code,m.start(),'The withdrawal path reduces recorded accounting by one amount but transfers a larger amount, creating a concrete conservation mismatch.',b,'Potential protocol loss equal to the unexplained excess transfer, subject to available balance.',.9))
  return fs
 def _line(self,code,pos):return code[:pos].count('\n')+1
 def _low(self,s):return {'critical':5000,'high':1000,'medium':500,'low':100}.get(s,100)
 def _high(self,s,c):return int({'critical':50000,'high':10000,'medium':5000,'low':1000}.get(s,1000)*(.5+c))
 def fuzz_contract(self,contract_abi,contract_address):return []
 def analyze_economics(self,protocol_params):return []
def generate_detailed_report(finding):
 if client is None:return f"# {finding.vulnerability_type}\n\n**Status:** {STATUS}\n\n## Severity\n{finding.severity.upper()}\n\n## Affected Location\n{finding.location}\n\n## Description\n{finding.description}\n\n## Evidence / PoC\n{finding.proof_of_concept}\n\n## Potential Impact\n{finding.economic_impact}\n\n## Confidence\n{finding.confidence*100:.0f}%\n\n## Human Verification\nReproduce in an explicitly authorized environment and confirm scope, impact, and duplicate status.\n\n## Remediation\nApply protocol-specific controls after confirming the root cause.\n\n## Submission Gate\nNever auto-submit; human approval is required."
 prompt=f"Create a professional Web3 security report for {finding.vulnerability_type}. Severity {finding.severity}; location {finding.location}; description {finding.description}; evidence {finding.proof_of_concept}; impact {finding.economic_impact}. Include executive summary, technical explanation, reproduction/PoC, impact, verification steps, remediation, and learning points. Clearly label {STATUS} and never suggest automatic submission."
 return client.messages.create(model=os.environ.get('ANTHROPIC_MODEL','claude-opus-4-1'),max_tokens=3000,messages=[{'role':'user','content':prompt}]).content[0].text

# Add the generalized semantic pass without replacing the existing analyzer core.
try:
 from semantic_dataflow import SemanticDataflow
 _core_analyze_protocol=AdvancedWeb3Analyzer.analyze_protocol
 def _analyze_with_semantics(self,code,protocol_name,network='ethereum'):
  base=_core_analyze_protocol(self,code,protocol_name,network)
  semantic=SemanticDataflow().analyze(code,protocol_name)
  semantic_categories={f.get('category') for f in semantic}
  # Legacy detectors are intentionally broad. If the semantic pass establishes a legitimate control pattern,
  # suppress only the corresponding broad legacy class; do not suppress unrelated detectors.
  suppressed={'oracle_attack','precision','delegatecall'}-semantic_categories
  base=[f for f in base if f.category not in suppressed]
  extra=[]
  for f in semantic:
   ev=(f.get('evidence') or [''])[0];anchor=ev[:40];pos=code.find(anchor) if anchor else 0
   if pos<0:pos=0
   conf=float(f.get('confidence',.72) or .72);sev=f.get('severity','medium')
   extra.append(self._finding('semantic',f.get('title',f.get('category','semantic')),sev,f.get('category','semantic'),code,pos,f.get('description',''),ev,'Semantic candidate requires local reproduction.',conf))
  merged={}
  for f in base+extra:
   k=(f.category,f.location,f.vulnerability_type)
   if k not in merged or f.confidence>merged[k].confidence: merged[k]=f
  self.findings=list(merged.values());return self.findings
 AdvancedWeb3Analyzer.analyze_protocol=_analyze_with_semantics
except Exception:
 pass
