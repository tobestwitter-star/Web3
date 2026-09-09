from evidence_classifier import EvidenceClassifier

def test_evidence_keeps_failed_probe_unconfirmed():
    result=EvidenceClassifier().classify(
        {'status':'executed','candidate_failed':True,'stdout':'[FAIL] assertion failed','stderr':'trace'},
        {'security_assertion':True}
    )
    assert result['evidence_level']=='security_assertion_failed'
    assert result['confirmed_vulnerability'] is False
    assert result['human_interpretation_required'] is True

def test_nonexecuted_probe_has_zero_reproducibility():
    result=EvidenceClassifier().classify({'status':'skipped','candidate_failed':False}, {})
    assert result['evidence_level']=='not_executed'
    assert result['reproducibility_score']==0.0
