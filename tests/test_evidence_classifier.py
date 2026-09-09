from evidence_classifier import EvidenceClassifier

def test_execution_without_assertion_is_not_reproduction():
    e=EvidenceClassifier().classify({'status':'executed','candidate_failed':True,'stdout':'trace call','stderr':''},{'security_assertion':False})
    assert e['evidence_level']=='execution_failed_without_security_assertion'
    assert e['confirmed_vulnerability'] is False
    assert e['status']=='UNVERIFIED — HUMAN REVIEW REQUIRED'

def test_failed_security_assertion_is_strong_candidate_evidence():
    e=EvidenceClassifier().classify({'status':'executed','candidate_failed':True,'stdout':'assertEq failed','stderr':''},{'security_assertion':True})
    assert e['evidence_level']=='security_assertion_failed'
    assert e['reproducibility_score']>.8
    assert e['confirmed_vulnerability'] is False
