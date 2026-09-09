"""Classify local validation evidence without overstating what a test proves."""
from __future__ import annotations
import re
from typing import Any, Dict
STATUS = 'UNVERIFIED — HUMAN REVIEW REQUIRED'

class EvidenceClassifier:
    def classify(self, execution: Dict[str, Any], harness: Dict[str, Any] | None = None) -> Dict[str, Any]:
        harness = harness or {}
        failed = bool(execution.get('candidate_failed'))
        assertion = bool(harness.get('security_assertion'))
        executed = execution.get('status') == 'executed'
        stderr = str(execution.get('stderr',''))
        stdout = str(execution.get('stdout',''))
        trace_text = stdout + '\n' + stderr
        traces = re.findall(r'(?m)^.*(?:\btrace\b|\bcall\b|\brevert\b|\bassert\w*\b).*$', trace_text, re.I)[:40]
        if not executed:
            level = 'not_executed'
        elif failed and assertion:
            level = 'security_assertion_failed'
        elif failed:
            level = 'execution_failed_without_security_assertion'
        else:
            level = 'executed_without_failure'
        reproducibility = 0.85 if level == 'security_assertion_failed' else 0.0
        if level == 'executed_without_failure': reproducibility = 0.05
        return {
            'evidence_level': level,
            'reproducibility_score': reproducibility,
            'security_assertion_present': assertion,
            'candidate_failed': failed,
            'trace_excerpt': traces,
            'status': STATUS,
            'confirmed_vulnerability': False,
            'human_interpretation_required': True,
        }
