from pathlib import Path
import shutil

import pytest

from mature_engine_runner import MatureEngineRunner

SLITHER_FIXTURE = Path(__file__).resolve().parents[1] / "benchmarks" / "slither_fixture"
FOUNDRY_FIXTURE = Path(__file__).resolve().parents[1] / "benchmarks" / "engine_fixture"


@pytest.mark.skipif(not shutil.which("slither"), reason="Slither binary is not installed in this environment")
def test_slither_real_execution_and_provenance():
    result = MatureEngineRunner().run_slither(str(SLITHER_FIXTURE), timeout=120)
    assert result["status"] == "completed"
    assert result["execution"]["returncode"] == 0
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


def test_foundry_does_not_mutate_non_foundry_target(tmp_path):
    (tmp_path / "Example.sol").write_text("pragma solidity ^0.8.20; contract Example {}\n", encoding="utf-8")
    result = MatureEngineRunner().run_foundry(str(tmp_path), timeout=10)
    assert result["status"] in {"not_applicable", "not_available"}
    assert not (tmp_path / "foundry.toml").exists()
