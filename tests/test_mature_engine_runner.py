from pathlib import Path
import shutil

import pytest

from mature_engine_runner import MatureEngineRunner

SLITHER_FIXTURE = Path(__file__).resolve().parents[1] / "benchmarks" / "slither_fixture"
FOUNDRY_FIXTURE = Path(__file__).resolve().parents[1] / "benchmarks" / "engine_fixture"


@pytest.mark.skipif(not shutil.which("slither"), reason="Slither binary is not installed in this environment")
def test_slither_real_execution_and_provenance():
    result = MatureEngineRunner().run_slither(str(SLITHER_FIXTURE), timeout=120)
    assert result["status"] in {"completed", "completed_with_findings"}
    assert result["execution"]["returncode"] != 0 or result["status"] == "completed"
    assert result["version"]
    assert result["evidence_provenance"]["stdout_sha256"]
    assert isinstance(result["findings"], list)


@pytest.mark.skipif(not shutil.which("forge"), reason="Foundry forge binary is not installed in this environment")
def test_foundry_real_execution_and_provenance():
    result = MatureEngineRunner().run_foundry(str(FOUNDRY_FIXTURE), timeout=120)
    assert result["status"] == "completed"
    assert result["execution"]["returncode"] == 0
    assert result["version"]
    assert result["evidence_provenance"]["stdout_sha256"]
    assert result["build_system"] == "foundry"


@pytest.mark.skipif(not shutil.which("halmos"), reason="Halmos binary is not installed in this environment")
def test_halmos_real_execution_and_json_provenance():
    result = MatureEngineRunner().run_halmos(str(FOUNDRY_FIXTURE), timeout=120)
    assert result["status"] in {"completed", "failed"}
    assert result["version"]
    assert result["build_system"] == "foundry"
    assert result["evidence_provenance"]["stdout_sha256"]
    assert "json_output_sha256" in result["evidence_provenance"]
    assert isinstance(result["findings"], list)


def test_ityfuzz_marks_real_bounded_execution(monkeypatch):
    runner = MatureEngineRunner()
    monkeypatch.setattr(
        runner,
        "inventory",
        lambda: {"ityfuzz": {"available": True, "path": "/bin/ityfuzz"}},
    )
    monkeypatch.setattr(runner, "_version", lambda *args: "ityfuzz test")
    monkeypatch.setattr(
        runner,
        "_run",
        lambda *args, **kwargs: {
            "status": "timeout",
            "error": "execution exceeded 15s timeout",
            "stdout": "EVM Fuzzer Start\nDeployed all contracts\nexecutions: 12345\n",
            "stderr": "",
            "returncode": None,
            "command": ["ityfuzz", "evm"],
            "cwd": str(FOUNDRY_FIXTURE),
        },
    )
    result = runner.run_ityfuzz(str(FOUNDRY_FIXTURE), timeout=15)
    assert result["status"] == "completed_bounded"
    assert result["bounded_execution"] is True
    assert result["execution"]["status"] == "timeout"


def test_foundry_does_not_mutate_non_foundry_target(tmp_path):
    (tmp_path / "Example.sol").write_text("pragma solidity ^0.8.20; contract Example {}\n", encoding="utf-8")
    result = MatureEngineRunner().run_foundry(str(tmp_path), timeout=10)
    assert result["status"] in {"not_applicable", "not_available"}
    assert not (tmp_path / "foundry.toml").exists()


def test_halmos_does_not_mutate_non_foundry_target(tmp_path):
    (tmp_path / "Example.sol").write_text("pragma solidity ^0.8.20; contract Example {}\n", encoding="utf-8")
    result = MatureEngineRunner().run_halmos(str(tmp_path), timeout=10)
    assert result["status"] in {"not_applicable", "not_available"}
    assert not (tmp_path / "foundry.toml").exists()
