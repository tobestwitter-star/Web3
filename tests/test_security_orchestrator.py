import tempfile
from pathlib import Path

from security_orchestrator import SecurityEngineOrchestrator


def test_orchestrator_inventory_distinguishes_available_tools(monkeypatch):
    monkeypatch.setattr("security_orchestrator.shutil.which", lambda name: "/bin/" + name)
    inventory = {x["name"]: x for x in SecurityEngineOrchestrator().inventory()}
    assert inventory["slither"]["available"] is True
    assert inventory["ityfuzz"]["available"] is True
    assert inventory["osv-scanner"]["available"] is True
    assert inventory["gitleaks"]["available"] is True


def test_orchestrator_selects_one_heavy_engine_for_reentrancy(monkeypatch):
    monkeypatch.setattr("security_orchestrator.shutil.which", lambda name: "/bin/" + name)
    calls = []
    def fake_run(command, cwd, timeout):
        calls.append(command[0])
        return {"status": "completed", "returncode": 0, "stdout": "{}", "stderr": ""}
    orch = SecurityEngineOrchestrator()
    monkeypatch.setattr(orch, "_run", fake_run)
    with tempfile.TemporaryDirectory() as td:
        root = Path(td); (root / "foundry.toml").write_text("")
        result = orch.run_for_candidates(td, [{"id": "f1", "title": "Reentrancy", "description": "external callback before state update", "priority": 80}], 10)
    assert result["decisions"][0]["question"] == "reentrancy"
    assert len(result["decisions"][0]["selected_engines"]) == 1
    assert result["decisions"][0]["selected_engines"][0] in {"ityfuzz", "halmos"}
    assert len(calls) == 1


def test_orchestrator_defers_deep_stage_without_candidates(monkeypatch):
    monkeypatch.setattr("security_orchestrator.shutil.which", lambda name: None)
    with tempfile.TemporaryDirectory() as td:
        root = Path(td); (root / "A.sol").write_text("contract A {}")
        result = SecurityEngineOrchestrator().orchestrate(td, findings=[])
    assert result["status"] == "orchestration_complete"
    assert result["stage2"]["decisions"] == []
    assert result["stage3"]["status"] == "deferred"
    assert result["findings_are_evidence_only"] is True
    assert result["review_status"] == "UNVERIFIED — HUMAN REVIEW REQUIRED"
