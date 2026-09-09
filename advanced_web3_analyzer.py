#!/usr/bin/env python3
"""Existing Web3 BugHunter analyzer, preserved as the core code-analysis engine.

The analyzer is deliberately evidence-gated: source signals become findings only
when the local code provides a plausible attacker capability and security impact.
All findings remain unverified until a human validates the complete attack path.
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
 def __init__(self): self.findings=[]; self.protocol_knowledge={}; self.exploit_patterns=[]
 def analyze_protocol(self,code,protocol_name,network="ethereum"):
  findings=self._specialized(code)+self._legacy_signals(code)
  out={}
  for f in findings:
   key=(f.category,f.location,f.vulnerability_type)
   if key not in out or f.confidence>out[key].confidence: out[key]=f
  self.findings=list(out.values()); return self.findings
 def _finding(self,key,name,severity,category,code,pos,desc,evidence,impact="Source-derived impact requires local reproduction.",confidence=.72):
  return Finding(f"{key}_{len(self.findings)}",name,severity,category,f"Source evidence near line {self._line(code,pos)}",desc,evidence[:1600],impact,confidence,self._low(severity),self._high(severity,confidence),confidence,True,"Validate the complete attacker path and security invariant locally.")
 def _functions(self,code):
  """Return Solidity function spans using brace balancing rather than a regex body."""
  out=[]
  for m in re.finditer(r'\bfunction\s+(\w+)\s*\(([^)]*)\)([^\{;]*)\{',code,re.I):
   depth=1;i=m.end()
   while i<len(code) and depth:
    if code[i]=='{': depth+=1
    elif code[i]=='}': depth-=1
    i+=1
   out.append((m,m.group(1),m.group(2),m.group(3),code[m.end():max(m.end(),i-1)]))
  return out
 def _has_auth(self,head,body):
  s=head+' '+body
  return bool(re.search(r'\b(?:onlyOwner|onlyRole|hasRole|_authorizeUpgrade|authorized|isOwner)\b',s,re.I) or re.search(r'\brequire\s*\([^;\n]{0,180}\b(?:msg\.sender|owner|admin|role)\b',s,re.I))
 def _state_write_after(self,body,pos):
  tail=body[pos:]
  return bool(re.search(r'\b(?:balance|balances|shares|debt|state|status|owner|admin|total[A-Za-z]*|allowance)\w*\s*(?:=|\+=|-=|\*=)',tail,re.I))
 def _sensitive_write(self,body):
  return bool(re.search(r'\b(?:balance|balances|shares|debt|owner|admin|implementation|pendingOwner|allowance|total[A-Za-z]*)\w*\s*(?:=|\+=|-=|\*=)',body,re.I))
 def _specialized(self,code):
  fs=[]; funcs=self._functions(code)
  # Signature/replay: require both cryptographic recovery and a security-sensitive mutation.
  if re.search(r'\becrecover\s*\(',code,re.I):
   for m,name,args,head,body in funcs:
    if not re.search(r'\becrecover\s*\(',body,re.I): continue
    security_action=bool(re.search(r'\b(?:claim|permit|execute|withdraw|mint|approve|transfer|setOwner|setAdmin)\w*\b',name,re.I)) or self._sensitive_write(body)
    freshness=bool(re.search(r'\b(?:nonce|used|usedHash|usedDigest|deadline|expiry|chainId|domainSeparator|DOMAIN_SEPARATOR|EIP712)\b',body,re.I))
    if security_action and not freshness:
     ev=body[:1800]
     fs.append(self._finding('signature_replay','Replayable signature authorization path','high','signature',code,m.start(),'The function recovers a signer and changes security-sensitive state, but the local authorization path shows no nonce, consumed digest, expiry, chain ID, or EIP-712-style domain binding.',ev,'Potential unauthorized repeated execution; exact asset impact requires local reproduction.',.86))
     fs.append(self._finding('replay','Missing signature replay protection','high','replay',code,m.start(),'A recovered-signature authorization appears reusable because the signed operation is not visibly bound to a one-time nonce/digest or expiry before state mutation.',ev,'Potential repeated execution of an otherwise valid authorization.',.84))
  # Initializer takeover: privileged state must be established by an externally reachable initializer.
  for m,name,args,head,body in funcs:
   if not re.fullmatch(r'(?:initialize|init|reinitialize)',name,re.I): continue
   privileged=bool(re.search(r'\b(?:owner|admin|implementation|pendingOwner|upgrader)\b\s*=',body,re.I))
   guard=bool(re.search(r'\b(?:initializer|reinitializer|onlyInitializing|initialized|require\s*\(\s*!?\s*initialized|_disableInitializers)\b',head+' '+body,re.I))
   if privileged and not guard:
    ev=body[:1500]
    fs.append(self._finding('initialization','Unprotected initializer / initialization takeover','critical','initialization',code,m.start(),'An externally reachable initializer assigns privileged control state without an observed one-time initialization guard.',ev,'An attacker may establish ownership/admin state before the legitimate initializer; impact depends on privileged functions.',.92))
    if re.search(r'\b(?:upgrade|implementation|upgrader)\b',code,re.I):
     fs.append(self._finding('init_upgrade','Initialization exposes upgrade privilege boundary','high','upgrade',code,m.start(),'The initialization path controls a privilege relevant to upgradeability and lacks an observed initialization guard.',ev,'Potential unauthorized upgrade/control if the initializer is reachable.',.88))
    fs.append(self._finding('init_privilege','Initialization privilege escalation','critical','privilege',code,m.start(),'A public initializer can establish owner/admin state without an observed authorization or one-time guard.',ev,'Potential takeover of privileged protocol operations.',.9))
  # Reentrancy/callback: call must precede a security-sensitive state effect. CEI or a mutex suppresses it.
  for m,name,args,head,body in funcs:
   call=re.search(r'(?:\b\w+\s*\.\s*(?:call|send|transfer)|\b(?:I\w+|[A-Z]\w*)\s*\([^;\n]{0,220}\))',body,re.I)
   if not call: continue
   guard=bool(re.search(r'\bnonReentrant\b|\blocked\s*=\s*true\b|\b_reentrancyGuard\b',head+' '+body,re.I))
   if guard: continue
   # Only flag a callback when a relevant state mutation follows it.
   if self._state_write_after(body,call.end()):
    ev=body[:1800]
    fs.append(self._finding('reentrancy','Reentrancy: external callback precedes state update','critical','reentrancy',code,m.start(),'An external call/callback occurs before a relevant state write and no obvious reentrancy mutex is present. This is an attack-path candidate, not confirmation.',ev,'Potential repeated or inconsistent state/value movement; local attacker callback reproduction is required.',.88))
    fs.append(self._finding('callback','Unsafe callback flow before accounting/state mutation','high','callback',code,m.start(),'An attacker-controlled recipient/interface callback executes before the caller finalizes a sensitive balance/state mutation.',ev,'Potential cross-function or callback reentrancy; impact requires local reproduction.',.82))
    fs.append(self._finding('external_call','Security-sensitive external call ordering','high','external_call',code,m.start(),'A cross-contract call precedes a relevant state mutation in the same callable path.',ev,'Potential callback-controlled state manipulation; validate the complete path locally.',.78))
  # Sensitive privilege mutations: identify concrete operations, not every public function.
  sensitive_names=r'^(?:upgrade|upgradeTo|upgradeToAndCall|mint|burn|pause|unpause|sweep|withdrawAll|transferOwnership|setOwner|setAdmin|setImplementation)$'
  for m,name,args,head,body in funcs:
   if not re.fullmatch(sensitive_names,name,re.I): continue
   if not self._sensitive_write(body) and not re.search(r'\b(?:transfer|call|delegatecall|selfdestruct)\b',body,re.I): continue
   if self._has_auth(head,body): continue
   ev=body[:1600]
   fs.append(self._finding('access_control','Sensitive operation lacks an observed authorization guard','high','access_control',code,m.start(),'A security-sensitive externally callable operation mutates privileged/value-bearing state without an observed owner, role, or authorization invariant.',ev,'Potential unauthorized privileged action; prove reachability and consequence locally.',.8))
   fs.append(self._finding('privilege','Privilege escalation path','high','privilege',code,m.start(),'A caller appears able to reach a privileged mutation without a visible authorization guard.',ev,'Potential unauthorized control/value movement.',.78))
  # Callback token accounting: distinguish an arbitrary recipient callback from a benign transfer.
  for m,name,args,head,body in funcs:
   if re.search(r'\b(?:safeTransfer|transfer|send|onTokenReceived|onERC)\b',body,re.I) and re.search(r'\b(?:IReceiver|onTokenReceived|onERC)\w*\s*\(',body,re.I):
    cb=re.search(r'\b(?:IReceiver|onTokenReceived|onERC)\w*\s*\(',body,re.I)
    if cb and self._state_write_after(body,cb.end()):
     fs.append(self._finding('callback_token','Token callback precedes balance accounting','high','callback',code,m.start(),'A receiver callback occurs before sender/recipient balances are finalized.',body[:1800],'Potential callback reentrancy or inconsistent token accounting.',.86))
     fs.append(self._finding('callback_asset','External callback asset-flow risk','high','external_call',code,m.start(),'A token transfer path invokes an external receiver before completing its accounting mutation.',body[:1800],'Potential unauthorized repeated transfer or accounting inconsistency.',.82))
  return fs
 def _legacy_signals(self,code):
  specs=[
   ('state_machine','State Machine Manipulation','critical','business_logic',[r'\b(?:state|status)\s*=',r'\b(?:transition|nextState)\b']),
   ('oracle','Oracle Manipulation / Price Attack','critical','oracle_attack',[r'\b(?:oracle|chainlink|latestAnswer|latestRoundData|getPrice|priceFeed|twap|spotPrice)\b']),
   ('flash','Flash Loan Attack Vector','critical','flash_loan',[r'\b(?:flashLoan|flashSwap)\b']),
   ('delegatecall','Unsafe delegatecall / upgrade surface','high','delegatecall',[r'\.(?:delegatecall|callcode)\s*\(']),
   ('precision','Precision / rounding risk','medium','precision',[r'\b(?:mulDiv|decimals|round|1e\d+|10\s*\*\*|/\s*\d+)\b']),
   ('accounting','Accounting invariant risk','high','accounting',[r'\b(?:totalAssets|totalSupply|shares|debt|reserve)\w*\s*(?:\+=|-=|=)'])]
  fs=[]
  for key,name,sev,cat,pats in specs:
   for p in pats:
    m=re.search(p,code,re.I)
    if not m: continue
    context=code[max(0,m.start()-180):min(len(code),m.end()+500)]
    # Legacy signals stay low-confidence and are explicitly hypotheses, not high-confidence findings.
    fs.append(self._finding(key,name,sev,cat,code,m.start(),'Source-level signal requiring an end-to-end attacker-path check.',context,'Impact is not quantified until local reproduction establishes the security consequence.',.58))
  return fs
 def _line(self,code,pos): return code[:pos].count('\n')+1
 def _low(self,severity): return {'critical':5000,'high':1000,'medium':500,'low':100}.get(severity,100)
 def _high(self,severity,confidence): return int({'critical':50000,'high':10000,'medium':5000,'low':1000}.get(severity,1000)*(.5+confidence))
 def fuzz_contract(self,contract_abi,contract_address): return []
 def analyze_economics(self,protocol_params): return []

def generate_detailed_report(finding):
 if client is None:
  return f"# {finding.vulnerability_type}\n\n**Status:** {STATUS}\n\n## Severity\n{finding.severity.upper()}\n\n## Affected Location\n{finding.location}\n\n## Description\n{finding.description}\n\n## Evidence / PoC\n{finding.proof_of_concept}\n\n## Potential Impact\n{finding.economic_impact}\n\n## Confidence\n{finding.confidence*100:.0f}%\n\n## Human Verification\nReproduce in an explicitly authorized environment and confirm scope, impact, and duplicate status.\n\n## Remediation\nApply protocol-specific controls after confirming the root cause.\n\n## Submission Gate\nNever auto-submit; human approval is required."
 prompt=f"Create a professional Web3 security report for {finding.vulnerability_type}. Severity {finding.severity}; location {finding.location}; description {finding.description}; evidence {finding.proof_of_concept}; impact {finding.economic_impact}. Include executive summary, technical explanation, reproduction/PoC, impact, verification steps, remediation, and learning points. Clearly label {STATUS} and never suggest automatic submission."
 return client.messages.create(model=os.environ.get('ANTHROPIC_MODEL','claude-opus-4-1'),max_tokens=3000,messages=[{'role':'user','content':prompt}]).content[0].text
