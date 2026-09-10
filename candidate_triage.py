from __future__ import annotations


UNVERIFIED = 'UNVERIFIED — HUMAN REVIEW REQUIRED'


def triage_finding(finding: dict) -> dict:
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
    else:
        out.setdefault('triage_classification', 'requires_reproduction')
        out.setdefault('bounty_candidate', True)
    out['status'] = UNVERIFIED
    return out
