"""Production-grade runners for the two core local security engines.

This module intentionally performs no target mutation. It executes only against a
caller-supplied local checkout and treats every engine observation as evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

STATUS = "UNVERIFIED — HUMAN REVIEW REQUIRED"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


class MatureEngineRunner:
    """Bounded, provenance-preserving execution for Slither and Foundry."""

    MAX_TIMEOUT = 180
    MAX_OUTPUT = 50000

    def inventory(self) -> Dict[str, Dict[str, Any]]:
        return {
            "slither": self._engine("slither", "AGPL-3.0-or-later", "crytic/slither"),
            "forge": self._engine("forge", "Apache-2.0 OR MIT", "foundry-rs/foundry"),
        }

    @staticmethod
    def _engine(binary: str, license_name: str, project: str) -> Dict[str, Any]:
        path = shutil.which(binary)
        return {"binary": binary, "path": path, "available": bool(path), "license": license_name, "project": project}

    @staticmethod
    def _build_system(source_dir: str) -> str:
        root = Path(source_dir)
        if (root / "foundry.toml").exists():
            return "foundry"
        if any((root / name).exists() for name in ("hardhat.config.js", "hardhat.config.ts", "hardhat.config.cjs", "hardhat.config.mjs")):
            return "hardhat"
        if (root / "package.json").exists():
            try:
                data = json.loads((root / "package.json").read_text(encoding="utf-8"))
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                if "hardhat" in deps:
                    return "hardhat"
            except (OSError, ValueError, TypeError):
                pass
        if list(root.rglob("*.sol")):
            return "solidity-generic"
        return "unknown"

    def _run(self, command: List[str], cwd: str, timeout: int) -> Dict[str, Any]:
        bounded = max(1, min(int(timeout), self.MAX_TIMEOUT))
        started = time.monotonic()
        try:
            proc = subprocess.run(command, cwd=cwd, text=True, capture_output=True, timeout=bounded)
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            return {
                "status": "completed" if proc.returncode == 0 else "failed",
                "returncode": proc.returncode,
                "stdout": stdout[-self.MAX_OUTPUT:],
                "stderr": stderr[-self.MAX_OUTPUT:],
                "stdout_sha256": _sha256(stdout),
                "stderr_sha256": _sha256(stderr),
                "duration_seconds": round(time.monotonic() - started, 3),
                "command": command,
                "cwd": os.path.abspath(cwd),
            }
        except FileNotFoundError:
            return {"status": "not_available", "error": f"executable not found: {command[0]}", "command": command}
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout or ""
            err = exc.stderr or ""
            if isinstance(out, bytes): out = out.decode("utf-8", "replace")
            if isinstance(err, bytes): err = err.decode("utf-8", "replace")
            return {
                "status": "timeout",
                "error": f"execution exceeded {bounded}s timeout",
                "stdout": out[-self.MAX_OUTPUT:],
                "stderr": err[-self.MAX_OUTPUT:],
                "stdout_sha256": _sha256(out),
                "stderr_sha256": _sha256(err),
                "duration_seconds": bounded,
                "command": command,
                "cwd": os.path.abspath(cwd),
            }
        except OSError as exc:
            return {"status": "failed", "error": str(exc), "command": command, "cwd": os.path.abspath(cwd)}

    def _version(self, binary: str, cwd: str) -> Optional[str]:
        if not shutil.which(binary):
            return None
        result = self._run([binary, "--version"], cwd, 15)
        if result.get("status") not in {"completed", "failed"}:
            return None
        text = (result.get("stdout", "") + "\n" + result.get("stderr", "")).strip()
        return text.splitlines()[0][:500] if text else None

    @staticmethod
    def _slither_findings(result: Dict[str, Any]) -> List[Dict[str, Any]]:
        try:
            data = json.loads(result.get("stdout", ""))
        except (TypeError, ValueError):
            return []
        detectors = data.get("results", {}).get("detectors", []) if isinstance(data, dict) else []
        findings: List[Dict[str, Any]] = []
        for detector in detectors if isinstance(detectors, list) else []:
            if not isinstance(detector, dict):
                continue
            elements = detector.get("elements") if isinstance(detector.get("elements"), list) else []
            locations = []
            for element in elements:
                if not isinstance(element, dict):
                    continue
                mapping = element.get("source_mapping") or {}
                filename = mapping.get("filename_relative") or mapping.get("filename_absolute")
                lines = mapping.get("lines") or []
                if filename:
                    locations.append({"file": filename, "lines": lines, "name": element.get("name"), "type": element.get("type")})
            impact = str(detector.get("impact") or "informational").lower()
            confidence = str(detector.get("confidence") or "medium").lower()
            findings.append({
                "id": detector.get("id") or detector.get("check"),
                "check": detector.get("check"),
                "title": detector.get("check") or "Slither detector",
                "description": detector.get("description") or "",
                "severity": impact,
                "confidence": {"high": 0.9, "medium": 0.7, "low": 0.45}.get(confidence, 0.55),
                "locations": locations,
                "evidence": elements,
                "engine_evidence": {"impact": impact, "confidence_label": confidence},
            })
        return findings

    @staticmethod
    def _forge_findings(result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert failed Foundry tests into validation evidence, not vulnerabilities."""
        text = (result.get("stdout", "") + "\n" + result.get("stderr", ""))
        failures = re.findall(r"(?m)^\s*(?:\[FAIL(?:ED)?\]|FAIL(?:ED)?:)\s*([^\n]+)", text)
        findings = []
        for failure in failures[:100]:
            findings.append({
                "id": _sha256("forge-test|" + failure)[:16],
                "title": "Foundry test failure",
                "description": failure.strip(),
                "severity": "informational",
                "confidence": 0.5,
                "category": "validation_evidence",
                "evidence": [{"test_failure": failure.strip(), "source": "forge test"}],
                "is_vulnerability": False,
            })
        return findings

    def run_slither(self, source_dir: str, timeout: int = 120) -> Dict[str, Any]:
        if not os.path.isdir(source_dir):
            return {"tool": "slither", "status": "failed", "error": "source directory does not exist", "findings": []}
        meta = self.inventory()["slither"]
        if not meta["available"]:
            return {"tool": "slither", "status": "not_available", "available": False, "error": "slither is not installed", "findings": []}
        result = self._run(["slither", ".", "--json", "-"], source_dir, timeout)
        findings = self._slither_findings(result)
        return {"tool": "slither", "status": result["status"], "available": True, "version": self._version("slither", source_dir), "execution": result, "findings": findings, "evidence_provenance": {"engine": "slither", "command": result.get("command"), "cwd": result.get("cwd"), "stdout_sha256": result.get("stdout_sha256"), "stderr_sha256": result.get("stderr_sha256")}, "review_status": STATUS}

    def run_foundry(self, source_dir: str, timeout: int = 120) -> Dict[str, Any]:
        if not os.path.isdir(source_dir):
            return {"tool": "forge", "status": "failed", "error": "source directory does not exist", "findings": []}
        meta = self.inventory()["forge"]
        if not meta["available"]:
            return {"tool": "forge", "status": "not_available", "available": False, "error": "forge is not installed", "findings": []}
        build_system = self._build_system(source_dir)
        if build_system != "foundry":
            return {"tool": "forge", "status": "not_applicable", "available": True, "build_system": build_system, "error": "Foundry project marker foundry.toml is absent; target was not mutated to create one", "findings": []}
        result = self._run(["forge", "test", "--json", "-vvv"], source_dir, timeout)
        return {"tool": "forge", "status": result["status"], "available": True, "version": self._version("forge", source_dir), "build_system": build_system, "execution": result, "findings": self._forge_findings(result), "evidence_provenance": {"engine": "forge", "command": result.get("command"), "cwd": result.get("cwd"), "stdout_sha256": result.get("stdout_sha256"), "stderr_sha256": result.get("stderr_sha256")}, "review_status": STATUS}

    def run_core(self, source_dir: str, timeout: int = 120) -> Dict[str, Any]:
        return {"status": "core_engine_execution_complete", "build_system": self._build_system(source_dir), "engines": [self.run_slither(source_dir, timeout), self.run_foundry(source_dir, timeout)], "review_status": STATUS}
