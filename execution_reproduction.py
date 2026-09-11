"""Authorized, bounded, hypothesis-driven local reproduction adapters.

This module deliberately accepts only local source directories and explicit research
hypotheses. It never turns a URL into an execution target and never treats a tool
failure or a raw tool finding as proof of exploitability.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

STATUS = "UNVERIFIED — HUMAN REVIEW REQUIRED"
DUPLICATE = "POSSIBLE DUPLICATE — HUMAN REVIEW REQUIRED"
EXECUTION_STATUSES = {
    "execution_attempted",
    "execution_completed",
    "vulnerability_reproduced",
    "vulnerability_not_reproduced",
    "execution_inconclusive",
    "execution_unavailable_or_blocked",
}


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, set):
        return sorted(_json_safe(v) for v in value)
    return value


def _stable(value: Any) -> str:
    return json.dumps(_json_safe(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


@dataclass(frozen=True)
class ResearchHypothesis:
    finding_id: str
    title: str
    category: str
    source_dir: str
    test_path: str
    expected_security_property: str
    authorized: bool = False
    scope_root: str = ""

    @classmethod
    def from_finding(cls, finding: Dict[str, Any], source_dir: str, test_path: str) -> "ResearchHypothesis":
        fid = str(finding.get("id") or "").strip()
        title = str(finding.get("title") or finding.get("vulnerability") or "").strip()
        category = str(finding.get("category") or "").strip().lower()
        prop = str(
            finding.get("expected_security_property")
            or finding.get("security_property")
            or finding.get("hypothesis")
            or ""
        ).strip()
        return cls(fid, title, category, os.path.abspath(source_dir), test_path, prop,
                   bool(finding.get("authorized", False)), str(finding.get("scope_root") or ""))

    def validate(self) -> Optional[str]:
        if not self.finding_id or not self.title:
            return "explicit research hypothesis/finding is required"
        if not self.category:
            return "hypothesis category is required"
        if not self.test_path or not self.expected_security_property:
            return "executable test path and expected security property are required"
        if not self.authorized:
            return "explicit authorization confirmation is required"
        root = Path(self.source_dir).resolve()
        if not root.is_dir():
            return "authorized local source directory does not exist"
        test = (root / self.test_path).resolve()
        if root not in test.parents and test != root:
            return "execution scope violation: test path escapes source root"
        if not test.is_file():
            return "executable reproduction test is unavailable"
        if self.scope_root:
            scope = Path(self.scope_root).resolve()
            if root != scope and scope not in root.parents and root not in scope.parents:
                return "execution scope violation: source root is outside authorized scope"
        return None


class BoundedExecutionAdapter:
    """Run one explicit local test with a hard wall-clock bound."""

    def __init__(self, runner: Optional[Callable[..., Any]] = None):
        self._runner = runner or subprocess.run

    def execute(self, hypothesis: ResearchHypothesis, engine: str, command: List[str], timeout: int = 180) -> Dict[str, Any]:
        error = hypothesis.validate()
        bounded = max(1, min(int(timeout), 180))
        if error:
            return {
                "status": "execution_unavailable_or_blocked",
                "reason": error,
                "engine": engine,
                "finding_id": hypothesis.finding_id,
                "command": command,
                "review_status": STATUS,
            }
        started = time.monotonic()
        try:
            proc = self._runner(
                command,
                cwd=hypothesis.source_dir,
                text=True,
                capture_output=True,
                timeout=bounded,
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            duration = round(time.monotonic() - started, 3)
            status = "execution_completed" if proc.returncode == 0 else "execution_attempted"
            return {
                "status": status,
                "engine": engine,
                "finding_id": hypothesis.finding_id,
                "command": command,
                "cwd": os.path.abspath(hypothesis.source_dir),
                "returncode": proc.returncode,
                "duration_seconds": duration,
                "stdout": stdout[-30000:],
                "stderr": stderr[-15000:],
                "stdout_sha256": _sha256(stdout),
                "stderr_sha256": _sha256(stderr),
                "review_status": STATUS,
            }
        except FileNotFoundError:
            return {
                "status": "execution_unavailable_or_blocked",
                "reason": f"tool not installed: {command[0]}",
                "engine": engine,
                "finding_id": hypothesis.finding_id,
                "command": command,
                "cwd": os.path.abspath(hypothesis.source_dir),
                "review_status": STATUS,
            }
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            if isinstance(stdout, bytes): stdout = stdout.decode("utf-8", "replace")
            if isinstance(stderr, bytes): stderr = stderr.decode("utf-8", "replace")
            return {
                "status": "execution_inconclusive",
                "reason": f"tool exceeded {bounded}s limit",
                "engine": engine,
                "finding_id": hypothesis.finding_id,
                "command": command,
                "cwd": os.path.abspath(hypothesis.source_dir),
                "duration_seconds": bounded,
                "stdout": stdout[-30000:],
                "stderr": stderr[-15000:],
                "stdout_sha256": _sha256(stdout),
                "stderr_sha256": _sha256(stderr),
                "review_status": STATUS,
            }


class ReproductionEvidence:
    """Classify raw execution without making an exploitability claim."""

    @staticmethod
    def classify(execution: Dict[str, Any], expected_security_property: str) -> Dict[str, Any]:
        if execution.get("status") == "execution_unavailable_or_blocked":
            outcome = "execution_unavailable_or_blocked"
        elif execution.get("status") == "execution_inconclusive":
            outcome = "execution_inconclusive"
        else:
            stdout = str(execution.get("stdout", ""))
            stderr = str(execution.get("stderr", ""))
            blob = stdout + "\n" + stderr
            parsed = None
            try:
                parsed = json.loads(stdout) if stdout.strip() else None
            except (TypeError, ValueError):
                parsed = None
            if stdout.strip() and parsed is None and "{" in stdout:
                outcome = "execution_inconclusive"
            elif execution.get("returncode") == 0:
                outcome = "vulnerability_not_reproduced"
            elif execution.get("returncode") not in (None, 0):
                # A failing test is only a candidate signal. It is a reproduction
                # only when an explicit security assertion/property is demonstrated.
                security_assertion = any(x in blob.lower() for x in (
                    "assertion failed", "security property violated", "invariant failed",
                    "counterexample", "exploit reproduced",
                ))
                outcome = "vulnerability_reproduced" if security_assertion and expected_security_property else "execution_attempted"
            else:
                outcome = "execution_inconclusive"
        return {
            "status": outcome,
            "expected_security_property": expected_security_property,
            "evidence": {
                "execution_status": execution.get("status"),
                "returncode": execution.get("returncode"),
                "stdout_sha256": execution.get("stdout_sha256"),
                "stderr_sha256": execution.get("stderr_sha256"),
            },
            "exploitability_claim": False,
            "review_status": STATUS,
        }


class ReproductionEngine:
    """Policy-aware Forge/ItyFuzz/Halmos adapter; no live-target execution."""

    COMMANDS = {
        "forge": lambda p: ["forge", "test", "--match-path", p, "-vvv", "--json"],
        "halmos": lambda p: ["halmos", "--match", p],
        "ityfuzz": lambda p: ["ityfuzz", "--target", p],
    }

    def __init__(self, executor: Optional[BoundedExecutionAdapter] = None):
        self.executor = executor or BoundedExecutionAdapter()

    def reproduce(self, hypothesis: ResearchHypothesis, engine: str = "forge", timeout: int = 180) -> Dict[str, Any]:
        if engine not in self.COMMANDS:
            return {"status": "execution_unavailable_or_blocked", "reason": "unsupported reproduction engine", "engine": engine, "finding_id": hypothesis.finding_id, "review_status": STATUS}
        binary = self.COMMANDS[engine](hypothesis.test_path)[0]
        if not shutil.which(binary):
            return {"status": "execution_unavailable_or_blocked", "reason": f"tool not installed: {binary}", "engine": engine, "finding_id": hypothesis.finding_id, "review_status": STATUS}
        execution = self.executor.execute(hypothesis, engine, self.COMMANDS[engine](hypothesis.test_path), timeout)
        evidence = ReproductionEvidence.classify(execution, hypothesis.expected_security_property)
        return {"engine": engine, "finding_id": hypothesis.finding_id, "execution": execution, "evidence": evidence, "review_status": STATUS}


def correlate_reproduction(original_finding: Dict[str, Any], runs: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Attach only authoritative reproduction observations to the original finding."""
    observations = []
    outcomes = []
    for run in runs:
        ev = run.get("evidence") or {}
        status = ev.get("status", "execution_inconclusive")
        outcomes.append(status)
        observations.append(_json_safe({
            "engine": run.get("engine"),
            "execution": run.get("execution", {}),
            "evidence": ev,
        }))
    reproduced = "vulnerability_reproduced" in outcomes
    not_reproduced = bool(outcomes) and all(x == "vulnerability_not_reproduced" for x in outcomes)
    if reproduced:
        classification = "vulnerability_reproduced"
    elif not_reproduced:
        classification = "vulnerability_not_reproduced"
    elif not outcomes:
        classification = "execution_unavailable_or_blocked"
    else:
        classification = "execution_inconclusive"
    merged = dict(original_finding)
    merged["reproduction"] = {
        "status": classification,
        "observations": observations,
        "conflicting_evidence": len(set(outcomes)) > 1,
        "repeatable": len(observations) >= 2 and len({
            _stable((o.get("evidence") or {}).get("evidence", {})) for o in observations
        }) == 1,
        "review_status": STATUS,
    }
    merged["status"] = STATUS
    merged["do_not_auto_submit"] = True
    merged["human_review_only"] = True
    return merged
