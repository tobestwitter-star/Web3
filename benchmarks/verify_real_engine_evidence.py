"""Verify real Forge/Halmos evidence through registry, reproduction, and report."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from execution_reproduction import ReproductionEvidence, correlate_reproduction
from professional_report import STATUS, build_professional_report

FIXTURES = ROOT / "benchmarks" / "protocol_fixtures"
HALMOS_FIXTURE = ROOT / "benchmarks" / "halmos_fixture"
OUT = ROOT / "benchmarks" / "results" / "real_engine_evidence.json"
MAX = 180


def sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def execute(command: list[str], cwd: Path, timeout: int = MAX) -> dict:
    started = time.monotonic()
    if not shutil.which(command[0]):
        return {
            "status": "execution_unavailable_or_blocked",
            "reason": f"tool not installed: {command[0]}",
            "command": command,
            "cwd": str(cwd.resolve()),
            "review_status": STATUS,
        }
    try:
        proc = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            capture_output=True,
            timeout=min(timeout, MAX),
        )
        stdout, stderr = proc.stdout or "", proc.stderr or ""
        return {
            "status": "execution_completed" if proc.returncode == 0 else "execution_attempted",
            "returncode": proc.returncode,
            "duration_seconds": round(time.monotonic() - started, 3),
            "stdout": stdout[-30000:],
            "stderr": stderr[-15000:],
            "stdout_sha256": sha(stdout),
            "stderr_sha256": sha(stderr),
            "command": command,
            "cwd": str(cwd.resolve()),
            "review_status": STATUS,
        }
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", "replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", "replace")
        return {
            "status": "execution_inconclusive",
            "reason": f"tool exceeded {timeout}s limit",
            "duration_seconds": timeout,
            "stdout": stdout[-30000:],
            "stderr": stderr[-15000:],
            "stdout_sha256": sha(stdout),
            "stderr_sha256": sha(stderr),
            "command": command,
            "cwd": str(cwd.resolve()),
            "review_status": STATUS,
        }


def main() -> int:
    prop = "credit must remain zero after the vulnerable state transition"
    finding = {
        "id": "real-engine-state-transition",
        "title": "State transition candidate",
        "category": "state_machine",
        "severity": "high",
        "confidence": 0.5,
        "location": "repository-local fixture",
        "expected_security_property": prop,
        "status": STATUS,
    }

    forge_execution = execute(
        ["forge", "test", "--match-test", "testStateMachineSecurityProperty", "-vvv"],
        FIXTURES,
    )
    forge_evidence = ReproductionEvidence.classify(forge_execution, prop)
    forge_run = {"engine": "forge", "execution": forge_execution, "evidence": forge_evidence}

    halmos_execution = execute(["halmos"], HALMOS_FIXTURE)
    halmos_blob = (halmos_execution.get("stdout", "") + "\n" + halmos_execution.get("stderr", "")).lower()
    symbolic = {
        "parse_status": "textual",
        "counterexample_count": halmos_blob.count("counterexample"),
        "symbolic_failure_observed": any(
            marker in halmos_blob
            for marker in ("assertion failed", "counterexample", "violated")
        ),
        "note": "Text is retained as engine-native output; no symbolic result is inferred from exit status alone.",
    }
    halmos_evidence = ReproductionEvidence.classify(halmos_execution, prop)
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
            {
                "engine": "forge",
                "stdout_sha256": forge_execution.get("stdout_sha256"),
                "stderr_sha256": forge_execution.get("stderr_sha256"),
            },
            {
                "engine": "halmos",
                "stdout_sha256": halmos_execution.get("stdout_sha256"),
                "stderr_sha256": halmos_execution.get("stderr_sha256"),
            },
        ],
    }

    report = build_professional_report(
        [correlated],
        {
            "id": "local-fixture",
            "name": "local protocol fixture",
            "source": "repository-local benchmark",
            "url": "file://local",
        },
        {
            "authorization_confirmed": True,
            "scope": "repository-local fixture only",
            "evidence_registry": {finding["id"]: registry},
        },
    )
    report_finding = report.get("findings", [{}])[0]

    forge_ok = forge_evidence.get("status") == "vulnerability_reproduced"
    halmos_symbolic_ok = bool(
        halmos_execution.get("status") in {"execution_completed", "execution_attempted"}
        and symbolic["symbolic_failure_observed"]
        and symbolic["counterexample_count"] > 0
    )
    preserved = bool(
        report_finding.get("engine_evidence")
        and report_finding.get("engine_provenance")
        and report_finding.get("execution_metadata")
        and report_finding.get("evidence_provenance")
        and report_finding.get("traces_inputs_coverage_symbolic", {}).get("symbolic")
        and report_finding.get("review_status") == STATUS
        and report.get("do_not_auto_submit") is True
        and report.get("human_review_only") is True
    )
    complete = bool(
        forge_ok
        and halmos_symbolic_ok
        and preserved
        and correlated["reproduction"]["status"] == "vulnerability_reproduced"
    )

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
            "forge_real_reproduction": forge_ok,
            "halmos_real_symbolic_counterexample": halmos_symbolic_ok,
            "independent_relevant_evidence_preserved": len(correlated["reproduction"]["observations"]) == 2,
            "registry_to_reproduction_to_report": preserved,
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
