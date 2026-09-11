from __future__ import annotations
import re

UNVERIFIED = 'UNVERIFIED — HUMAN REVIEW REQUIRED'


def _uninitialized_interface_is_unreachable(finding: dict, source_code: str | None) -> bool:
    """Reject a specific static false positive: an uninitialized interface call.

    An interface storage pointer defaults to address(0). If the only observed use
    is an external interface call and there is no assignment path, Solidity cannot
    obtain the expected ABI return tuple; the callable path reverts rather than
    producing the claimed protocol state change. This is a semantic gate, not a
    general suppression of Slither's uninitialized-state detector.
    """
    if not source_code or str(finding.get('title') or '').lower() != 'uninitialized-state':
        return False
    description = str(finding.get('description') or '')
    m = re.search(r'\b([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\s*\(', description)
    if not m:
        return False
    variable, _ = m.group(1), m.group(2)
    declaration = re.search(r'\binterface\s+([A-Za-z_$][\w$]*)\b[\s\S]{0,500}?\b' + re.escape(variable) + r'\s+public\s+' + re.escape(variable) + r'\s*;', source_code)
    if not declaration:
        declaration = re.search(r'\b([A-Za-z_$][\w$]*)\s+public\s+' + re.escape(variable) + r'\s*;', source_code)
    if not declaration:
        return False
    assignment = re.search(r'\b' + re.escape(variable) + r'\s*=', source_code)
    external_use = re.search(r'\b' + re.escape(variable) + r'\s*\.\s*\w+\s*\(', source_code)
    return bool(external_use and not assignment)


def triage_finding(finding: dict, source_code: str | None = None) -> dict:
    """Apply conservative semantic gates before a static candidate becomes bounty-facing.

    This never upgrades a finding. It only records strong reasons that the claimed
    security consequence is inconsistent with the attributed source semantics.
    """
    out = dict(finding)
    attr = out.get('source_attribution') or {}
    mutability = attr.get('mutability')
    title = str(out.get('title') or '').lower()
    description = str(out.get('description') or '').lower()
    claim = f'{title} {description}'
    if mutability in {'view', 'pure'} and any(x in claim for x in (
        'state update', 'state mutation', 'privilege mutation', 'authorization',
        'reentrancy', 'accounting', 'asset flow', 'writes storage')):
        out['triage_classification'] = 'false_positive'
        out['triage_reason'] = f'Attributed function is {mutability}; the claimed consequence requires a state mutation that this function cannot perform.'
        out['bounty_candidate'] = False
    elif _uninitialized_interface_is_unreachable(out, source_code):
        out['triage_classification'] = 'false_positive'
        out['triage_reason'] = 'The uninitialized interface pointer has no assignment path and its required external call is unreachable as a successful state-changing operation because the zero-address call cannot return the expected ABI data.'
        out['bounty_candidate'] = False
        out['semantic_gate'] = 'uninitialized_interface_call_reverts'
    else:
        out.setdefault('triage_classification', 'requires_reproduction')
        out.setdefault('bounty_candidate', True)
    out['status'] = UNVERIFIED
    return out
