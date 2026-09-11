"""Verify the real-engine -> registry -> reproduction -> report path on local fixtures only."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from execution_reproduction import ReproductionEvidence, correlate_reproduction
from professional_report import STATUS, build_professional_report

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "benchmarks" / "protocol_fixtures"
HALMOS_FIXTURE = ROOT / "benchmarks" / "halmos_fixture"
OUT = ROOT / "benchmarks" / "results" / "real_engine_evidence.json"
MAX = 180


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def execute(command: list[str], cwd: Path, timeout: int = MAX) -> dict:
    started = time.monotonic()
    if not shutil.which(command[0]):
        return {"status": "unavailable", "reason": f"tool not installed: {command[0]}", "command": command, "cwd": str(cwd.resolve())}
    try:
        proc = subprocess.run(command, cwd=cwd, text=True, capture_output=True, timeout=min(timeout, MAX))
        stdout, stderr = proc.stdout or "", proc.stderr or ""
        return {
            "status": "completed" if proc.returncode == 0 else "failed",
            "returncode": proc.returncode,
            "duration_seconds": round(time.monotonic() - started, 3),
            "stdout": stdout[-30000:],
            "stderr": stderr[-15000:],
            "stdout_sha256": sha(stdout),
            "stderr_sha256": sha(stderr),
            "command": command,
            "cwd": str(cwd.resolve()),
        }
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes): stdout = stdout.decode("utf-8", "replace")
        if isinstance(stderr, bytes): stderr = stderr.decode("utf-8", "replace")
        return {
            "status": "timeout",
            "duration_seconds": min(timeout, MAX),
            "stdout": stdout[-30000:],
            "stderr": stderr[-15000:],
            "stdout_sha256": sha(stdout),
            "stderr_sha256": sha(stderr),
            "command": command,
            "cwd": str(cwd.resolve()),
        }


def halmos_json(execution: dict, path: Path) -> dict:
    if not path.exists():
        return {"parse_status": "missing", "tests": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        tests = [test for rows in data.get("test_results", {}).values() for test in rows]
        return {
            "parse_status": "ok",
            "exitcode": data.get("exitcode"),
            "tests": tests,
            "counterexample_count": sum(int(t.get("num_models", 0)) for t in tests),
        }
    except Exception as exc:
        return {"parse_status": "error", "error": str(exc), "tests": []}


def main() -> int:
    property_text = "credit must remain zero after an unauthorized state transition"
    finding = {
        "id": "real-engine-state-transition",
        "title": "Unauthorized state transition candidate",
        "category": "state_machine",
        "severity": "high",
        "confidence": 0.5,
        "location": "local fixture",
        "expected_security_property": property_text,
        "status": STATUS,
    }

    forge_execution = execute(
        ["forge", "test", "--match-test", "testStateMachineSecurityProperty", "-vvv"],
        FIXTURES,
    )
    forge_evidence = ReproductionEvidence.classify(forge_execution, property_text)
    forge_run = {"engine": "forge", "execution": forge_execution, "evidence": forge_evidence}

    symbolic_path = Path(tempfile.mkstemp(prefix="halmos-real-", suffix=".json")[1])
    symbolic_path.unlink(missing_ok=True)
    try:
        halmos_execution = execute(
            ["halmos", "--json-output", str(symbolic_path)],
            HALMOS_FIXTURE,
        )
        symbolic = halmos_json(halmos_execution, symbolic_path)
    finally:
        symbolic_path.unlink(missing_ok=True)
    halmos_evidence = ReproductionEvidence.classify(halmos_execution, property_text)
    halmos_run = {"engine": "halmos", "execution": halmos_execution, "evidence": halmos_evidence}

    correlated = correlate_reproduction(finding, [forge_run, halmos_run])
    registry = {
        "real_engine": True,
        "engine_observations": correlated["reproduction"]["observations"],
        "reproduction": correlated["reproduction"],
        "engine_provenance": [
            {"engine": "forge", "version_source": "actual subprocess execution"},
            {"engine": "halmos", "version_source": "actual subprocess execution"},
        ],
        "execution_metadata": [forge_execution, halmos_execution],
        "symbolic": symbolic,
        "provenance": [
            {"engine": "forge", "stdout_sha256": forge_execution.get("stdout_sha256"), "stderr_sha256": forge_execution.get("stderr_sha256")},
            {"engine": "halmos", "stdout_sha256": halmos_execution.get("stdout_sha256"), "stderr_sha256": halmos_execution.get("stderr_sha256")},
        ],
    }
    report = build_professional_report(
        [correlated],
        {"id": "local-fixture", "name": "local protocol fixture", "source": "repository-local benchmark", "url": "file://local"},
        {"authorization_confirmed": True, "scope": "repository-local fixture only", "evidence_registry": {finding["id"]: registry}},
    )

    report_finding = report["findings"][0]
    forge_reproduced = forge_evidence["status"] == "vulnerability_reproduced"
    halmos_reproduced = halmos_evidence["status"] == "vulnerability_reproduced"
    registry_preserved = (
        report_finding.get("engine_evidence")
        and report_finding.get("engine_provenance")
        and report_finding.get("execution_metadata")
        and report_finding.get("evidence_provenance")
        and report_finding.get("traces_inputs_coverage_symbolic", {}).get("symbolic")
        and report_finding.get("review_status") == STATUS
        and report.get("do_not_auto_submit") is True
        and report.get("human_review_only") is True
    )
    complete = bool(forge_reproduced and halmos_reproduced and registry_preserved and correlated["reproduction"]["status"] == "vulnerability_reproduced")

    payload = {
        "benchmark": "real-engine-evidence-path",
        "authorized_scope": "repository-local fixture only",
        "max_execution_seconds": MAX,
        "status": STATUS,
        "engines": {"forge": forge_execution, "halmos": halmos_execution},
        "symbolic_evidence": symbolic,
        "correlation": correlated["reproduction"],
        "evidence_registry": registry,
        "professional_report_projection": report,
        "checks": {
            "forge_real_reproduction": forge_reproduced,
            "halmos_real_symbolic_counterexample": halmos_reproduced and symbolic.get("counterexample_count", 0) > 0,
            "independent_relevant_evidence_preserved": len(correlated["reproduction"]["observations"]) == 2,
            "registry_to_reproduction_to_report": bool(registry_preserved),
            "no_auto_submission": report.get("do_not_auto_submit") is True,
            "human_review_only": report.get("human_review_only") is True,
            "complete": complete,
        },
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
