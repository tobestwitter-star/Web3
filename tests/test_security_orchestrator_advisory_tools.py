from security_orchestrator import SecurityEngineOrchestrator


def test_osv_json_is_normalized_with_source_location():
    payload = {
        "results": [{
            "source": {"path": "/tmp/package-lock.json", "type": "lockfile"},
            "packages": [{
                "package": {"name": "demo", "version": "1.0.0", "ecosystem": "npm"},
                "vulnerabilities": [{"id": "GHSA-demo", "aliases": ["CVE-2099-0001"], "summary": "demo issue"}],
            }],
        }]
    }
    result = SecurityEngineOrchestrator._specialized_findings("osv-scanner", {"stdout": __import__("json").dumps(payload)})
    assert len(result) == 1
    assert result[0]["id"] == "GHSA-demo"
    assert result[0]["file"] == "/tmp/package-lock.json"
    assert result[0]["category"] == "dependency_vulnerability"


def test_gitleaks_json_is_normalized_with_line_location():
    payload = [{"RuleID": "aws-access-token", "Description": "AWS key", "File": "src/a.py", "StartLine": 7}]
    result = SecurityEngineOrchestrator._specialized_findings("gitleaks", {"stdout": __import__("json").dumps(payload)})
    assert len(result) == 1
    assert result[0]["id"] == "aws-access-token"
    assert result[0]["location"] == "src/a.py:7"
    assert result[0]["category"] == "secret_exposure"
