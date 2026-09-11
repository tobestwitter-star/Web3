import os
from pathlib import Path

from execution_reproduction import (
    BoundedExecutionAdapter,
    DUPLICATE,
    ResearchHypothesis,
    ReproductionEvidence,
    correlate_reproduction,
)


def _hypothesis(tmp_path, authorized=True):
    test = tmp_path / "repro.t.sol"
    test.write_text("// bounded reproduction fixture\n")
    return ResearchHypothesis(
        finding_id="f-1",
        title="Candidate",
        category="reentrancy",
        source_dir=str(tmp_path),
        test_path="repro.t.sol",
        expected_security_property="attacker cannot withdraw more than deposited balance",
        authorized=authorized,
    )


def _runner(stdout="", stderr="", returncode=0, timeout=None):
    def run(command, **kwargs):
        class P:
            pass
        if timeout == "raise":
            import subprocess
            raise subprocess.TimeoutExpired(command, kwargs.get("timeout"), output=stdout, stderr=stderr)
        p = P(); p.stdout = stdout; p.stderr = stderr; p.returncode = returncode
        return p
    return run


def test_successful_bounded_reproduction_is_completed(tmp_path):
    h = _hypothesis(tmp_path)
    r = BoundedExecutionAdapter(_runner(stdout='{"status":"ok"}')).execute(h, "forge", ["forge", "test"], 999)
    assert r["status"] == "execution_completed"
    assert r["duration_seconds"] <= 180
    assert r["stdout_sha256"]


def test_failed_reproduction_is_not_automatically_a_vulnerability(tmp_path):
    h = _hypothesis(tmp_path)
    r = BoundedExecutionAdapter(_runner(stdout="ordinary test failure", returncode=1)).execute(h, "forge", ["forge", "test"], 10)
    e = ReproductionEvidence.classify(r, h.expected_security_property)
    assert e["status"] == "execution_attempted"
    assert e["exploitability_claim"] is False


def test_explicit_security_assertion_can_classify_reproduction(tmp_path):
    h = _hypothesis(tmp_path)
    r = BoundedExecutionAdapter(_runner(stdout="Assertion failed: security property violated", returncode=1)).execute(h, "forge", ["forge", "test"], 10)
    e = ReproductionEvidence.classify(r, h.expected_security_property)
    assert e["status"] == "vulnerability_reproduced"
    assert e["exploitability_claim"] is False


def test_inconclusive_malformed_output(tmp_path):
    h = _hypothesis(tmp_path)
    r = BoundedExecutionAdapter(_runner(stdout="{not-json}", returncode=0)).execute(h, "forge", ["forge", "test"], 10)
    e = ReproductionEvidence.classify(r, h.expected_security_property)
    assert e["status"] == "execution_inconclusive"


def test_timeout_is_inconclusive_and_bounded(tmp_path):
    h = _hypothesis(tmp_path)
    r = BoundedExecutionAdapter(_runner(timeout="raise")).execute(h, "forge", ["forge", "test"], 999)
    assert r["status"] == "execution_inconclusive"
    assert r["duration_seconds"] == 180


def test_missing_engine_is_unavailable(tmp_path):
    h = _hypothesis(tmp_path)
    # Use a direct adapter to exercise the missing-binary path without executing anything.
    import execution_reproduction as er
    old = er.shutil.which
    er.shutil.which = lambda _: None
    try:
        result = er.ReproductionEngine().reproduce(h, "forge", 10)
    finally:
        er.shutil.which = old
    assert result["status"] == "execution_unavailable_or_blocked"


def test_unauthorized_execution_rejected(tmp_path):
    h = _hypothesis(tmp_path, authorized=False)
    called = {"value": False}
    def runner(*args, **kwargs):
        called["value"] = True
        raise AssertionError("runner must not execute")
    r = BoundedExecutionAdapter(runner).execute(h, "forge", ["forge", "test"], 10)
    assert r["status"] == "execution_unavailable_or_blocked"
    assert called["value"] is False


def test_scope_violation_rejected(tmp_path):
    outside = tmp_path / "outside.t.sol"
    outside.write_text("fixture")
    h = ResearchHypothesis("f-1", "Candidate", "reentrancy", str(tmp_path), "../outside.t.sol", "property", True)
    r = BoundedExecutionAdapter(_runner()).execute(h, "forge", ["forge", "test"], 10)
    assert r["status"] == "execution_unavailable_or_blocked"
    assert "scope violation" in r["reason"]


def test_repeatable_evidence_ignores_duration(tmp_path):
    h = _hypothesis(tmp_path)
    a = BoundedExecutionAdapter(_runner(stdout='{"counterexample":"same"}', returncode=1)).execute(h, "forge", ["forge", "test"], 10)
    b = BoundedExecutionAdapter(_runner(stdout='{"counterexample":"same"}', returncode=1)).execute(h, "forge", ["forge", "test"], 10)
    ea = ReproductionEvidence.classify(a, h.expected_security_property)
    eb = ReproductionEvidence.classify(b, h.expected_security_property)
    combined = correlate_reproduction({"id":"f-1","review_status":"UNVERIFIED — HUMAN REVIEW REQUIRED"}, [
        {"engine":"forge","execution":a,"evidence":ea},
        {"engine":"forge","execution":b,"evidence":eb},
    ])
    assert combined["reproduction"]["repeatable"] is True
    assert combined["reproduction"]["conflicting_evidence"] is False


def test_conflicting_reproduction_evidence_is_preserved(tmp_path):
    h = _hypothesis(tmp_path)
    a = {"engine":"forge","execution":{"status":"execution_completed"},"evidence":{"status":"vulnerability_not_reproduced","evidence":{"stdout_sha256":"a"}}}
    b = {"engine":"halmos","execution":{"status":"execution_completed"},"evidence":{"status":"vulnerability_reproduced","evidence":{"stdout_sha256":"b"}}}
    result = correlate_reproduction({"id":"f-1"}, [a,b])
    assert result["reproduction"]["status"] == "vulnerability_reproduced"
    assert result["reproduction"]["conflicting_evidence"] is True
    assert len(result["reproduction"]["observations"]) == 2


def test_report_propagation_preserves_review_and_submission_guards(tmp_path):
    result = correlate_reproduction({"id":"f-1","duplicate_classification":DUPLICATE}, [])
    assert result["status"] == "UNVERIFIED — HUMAN REVIEW REQUIRED"
    assert result["do_not_auto_submit"] is True
    assert result["human_review_only"] is True
    assert result["duplicate_classification"] == DUPLICATE
