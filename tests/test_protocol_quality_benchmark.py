from benchmarks.run_protocol_quality import run
from protocol_validation import correlate_execution_evidence


def test_protocol_quality_benchmark_passes():
    assert run() == 0


def test_unrelated_engine_evidence_cannot_raise_confidence():
    base = {"engine": "forge", "finding_id": "f1", "hypothesis_id": "h1", "security_invariant": "I", "security_assertion": True, "invariant_result": "violated", "outcome": "reproduced", "returncode": 1, "stdout_sha256": "a", "stderr_sha256": "b"}
    same = correlate_execution_evidence([base])
    unrelated = correlate_execution_evidence([base, {**base, "engine": "halmos", "finding_id": "f2", "hypothesis_id": "h2"}])
    assert unrelated["relevant_independent_engine_count"] == 0
    assert unrelated["confidence_delta"] == same["confidence_delta"]
