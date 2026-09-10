from candidate_triage import triage_finding

def test_view_state_mutation_claim_is_false_positive():
    out=triage_finding({'title':'Sensitive privilege mutation lacks authorization','source_attribution':{'mutability':'view'}})
    assert out['triage_classification']=='false_positive'
    assert out['bounty_candidate'] is False
    assert out['status']=='UNVERIFIED — HUMAN REVIEW REQUIRED'

def test_mutating_candidate_requires_reproduction():
    out=triage_finding({'title':'Reentrancy: external call precedes state update','source_attribution':{'mutability':'nonpayable'}})
    assert out['triage_classification']=='requires_reproduction'
    assert out['bounty_candidate'] is True
