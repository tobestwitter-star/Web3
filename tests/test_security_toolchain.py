import tempfile
from pathlib import Path
from security_toolchain import SecurityToolchain

def test_inventory_is_non_destructive():
    tools=SecurityToolchain().inventory()
    assert {t['name'] for t in tools}=={'slither','aderyn','forge','echidna','medusa','wake','halmos','ityfuzz','osv-scanner','gitleaks'}
    assert all('license' in t and 'project' in t for t in tools)

def test_analysis_requires_local_directory():
    result=SecurityToolchain().analyze('/definitely/not/a/real/path')
    assert result['authorized_local_analysis_only'] is True
    assert result['build']['error']=='source directory does not exist'

def test_build_detection_foundry_and_hardhat():
    with tempfile.TemporaryDirectory() as td:
        root=Path(td);(root/'foundry.toml').write_text('');(root/'hardhat.config.ts').write_text('');(root/'A.sol').write_text('contract A {}')
        d=SecurityToolchain().detect_build(td)
        assert d['primary']=='foundry' and {x['system'] for x in d['detected']}=={'foundry','hardhat'}

def test_slither_machine_output_parser():
    result={'stdout':'{"results":{"detectors":[{"check":"reentrancy","impact":"High","confidence":"High","description":"callback before state update","elements":[]}]}}','stderr':''}
    findings=SecurityToolchain().parse_result('slither',result)
    assert findings[0]['title']=='reentrancy' and findings[0]['severity']=='high' and findings[0]['confidence']==.85

def test_upgrade_surface_is_source_derived():
    with tempfile.TemporaryDirectory() as td:
        root=Path(td)
        (root/'Proxy.sol').write_text('contract Proxy { function upgradeTo(address impl) external { address(impl).delegatecall(""); } }')
        result=SecurityToolchain().upgrade_surface(td)
        assert {'proxy','delegatecall'} <= set(result['risk_classes'])
        assert result['status']=='UNVERIFIED — HUMAN REVIEW REQUIRED'

def test_symbolic_missing_tool_is_safe_skip():
    with tempfile.TemporaryDirectory() as td:
        result=SecurityToolchain().run_symbolic(td,1)
        assert result['confirmed_vulnerability'] is False
        assert result['review_status']=='UNVERIFIED — HUMAN REVIEW REQUIRED'
