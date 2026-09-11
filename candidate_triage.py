from __future__ import annotations
import re
UNVERIFIED='UNVERIFIED — HUMAN REVIEW REQUIRED'

def _uninitialized_interface_is_unreachable(finding,source_code):
    if not source_code or str(finding.get('title') or '').lower()!='uninitialized-state': return False
    d=str(finding.get('description') or '');m=re.search(r'\b[A-Za-z_$][\w$]*\.([A-Za-z_$][\w$]*)\s*\(',d)
    if not m: m=re.search(r'\b[A-Za-z_$][\w$]*\.([A-Za-z_$][\w$]*)\s*\(',d+'(')
    if not m:return False
    v=m.group(1);im=re.search(r'\binterface\s+([A-Za-z_$][\w$]*)\b',source_code)
    if not im:return False
    typ=im.group(1)
    return bool(re.search(r'\b'+re.escape(typ)+r'\s+public\s+'+re.escape(v)+r'\s*;',source_code) and re.search(r'\b'+re.escape(v)+r'\s*\.\s*\w+\s*\(',source_code) and not re.search(r'\b'+re.escape(v)+r'\s*=',source_code))

def _state_transition_is_constrained(finding,source_code):
    if not source_code or str(finding.get('title') or '').lower() not in {'state machine manipulation','unrestricted state-machine transition','business logic invariant failure'}: return False
    loc=str(finding.get('location') or '');lm=re.search(r'line\s+(\d+)',loc,re.I);target=int(lm.group(1)) if lm else None
    funcs=list(re.finditer(r'function\s+\w+\s*\([^)]*\)[^{;]*\{([\s\S]*?)\}',source_code,re.I))
    for fm in funcs:
        start=source_code[:fm.start()].count('\n')+1;end=source_code[:fm.end()+len(fm.group(1))].count('\n')+1;body=fm.group(1)
        if target is not None and not(start<=target<=end): continue
        if re.search(r'\brequire\s*\([^;\n]*(?:state|status|phase|mode)\b',body,re.I): return True
        if re.search(r'\brequire\s*\(\s*(?:state|status|phase|mode)\w*\s*==\s*type\s*\(\s*uint256\s*\)\.max\s*\)',body,re.I): return True
        return False
    return False

def _callback_claim_has_real_external_call(finding,source_code):
    if not source_code or 'callback' not in str(finding.get('title') or '').lower(): return True
    return bool(re.search(r'\.(?:call|send|transfer)\s*\(|\b(?:call|send|transfer)\s*\(|\bI[A-Za-z_$][\w$]*\s*\(',source_code,re.I))

def _flash_loan_has_asset_boundary(finding,source_code):
    if not source_code or 'flash loan' not in str(finding.get('title') or '').lower(): return True
    return bool(re.search(r'\.(?:call|send|transfer)\s*\(|\b(?:transfer|send|call)\s*\(',source_code,re.I))

def _precision_is_exact(finding,source_code):
    if not source_code or 'precision' not in str(finding.get('category') or '').lower() and 'precision' not in str(finding.get('title') or '').lower(): return False
    return bool(re.search(r'\b\w+\s*\*\s*(\d+)\s*/\s*\1\b',source_code))

def triage_finding(finding,source_code=None):
    out=dict(finding);attr=out.get('source_attribution') or {};mutability=attr.get('mutability');title=str(out.get('title') or '').lower();desc=str(out.get('description') or '').lower();claim=f'{title} {desc}'
    if mutability in {'view','pure'} and any(x in claim for x in ('state update','state mutation','privilege mutation','authorization','reentrancy','accounting','asset flow','writes storage')):
        out['triage_classification']='false_positive';out['triage_reason']=f'Attributed function is {mutability}; the claimed consequence requires a state mutation that this function cannot perform.';out['bounty_candidate']=False
    elif _uninitialized_interface_is_unreachable(out,source_code):
        out['triage_classification']='false_positive';out['triage_reason']='The uninitialized interface pointer has no assignment path and its required external call cannot successfully return the expected ABI data from the zero address.';out['bounty_candidate']=False;out['semantic_gate']='uninitialized_interface_call_reverts'
    elif _state_transition_is_constrained(out,source_code):
        out['triage_classification']='false_positive';out['triage_reason']='The specific flagged transition is constrained by a predecessor-state or unreachable sentinel precondition.';out['bounty_candidate']=False;out['semantic_gate']='state_transition_precondition'
    elif title in {'token callback precedes balance accounting','cross-contract callback precedes state finalization'} and not _callback_claim_has_real_external_call(out,source_code):
        out['triage_classification']='false_positive';out['triage_reason']='The source does not contain an outbound callback-capable external call on the claimed path; an externally callable callback-shaped function is not itself proof of callback reentrancy.';out['bounty_candidate']=False;out['semantic_gate']='no_outbound_callback'
    elif 'flash loan' in title and not _flash_loan_has_asset_boundary(out,source_code):
        out['triage_classification']='false_positive';out['triage_reason']='The flash-loan-shaped function has no external asset transfer/callback boundary, so the static label does not establish an economic attack path.';out['bounty_candidate']=False;out['semantic_gate']='no_asset_boundary'
    elif _precision_is_exact(out,source_code):
        out['triage_classification']='false_positive';out['triage_reason']='The flagged multiplication/division uses an identical scale factor in numerator and denominator, so the operation is exact and introduces no truncation.';out['bounty_candidate']=False;out['semantic_gate']='exact_scale_factor'
    else: out.setdefault('triage_classification','requires_reproduction');out.setdefault('bounty_candidate',True)
    out['status']=UNVERIFIED;return out
