from pathlib import Path

from advanced_web3_analyzer import AdvancedWeb3Analyzer

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "benchmarks" / "fixtures"

def scan(name):
    code = (FIXTURES / f"{name}.sol").read_text(encoding="utf-8")
    return AdvancedWeb3Analyzer().analyze_protocol(code, name)

def categories(name):
    return {f.category for f in scan(name)}

def test_reentrancy_regression_and_safe_control():
    assert {"reentrancy", "external_call"}.issubset(categories("ReentrancyVault"))
    assert "reentrancy" not in categories("ReentrancySafe")

def test_access_control_regression_and_safe_control():
    assert {"access_control", "privilege"}.issubset(categories("AccessControlVault"))
    assert "access_control" not in categories("AccessControlSafe")

def test_signature_replay_regression_and_safe_control():
    assert {"signature", "replay"}.issubset(categories("SignatureReplay"))
    assert "signature" not in categories("SignatureSafe")
    assert "replay" not in categories("SignatureSafe")

def test_initializer_regression_and_safe_control():
    assert {"initialization", "upgrade", "privilege"}.issubset(categories("InitializerBug"))
    assert "initialization" not in categories("InitializerSafe")

def test_callback_regression_and_safe_control():
    assert {"callback", "external_call"}.issubset(categories("CallbackToken"))
    assert "callback" not in categories("CallbackSafe")

def test_existing_core_classes_remain_detected():
    assert "accounting" in categories("AccountingPool")
    assert "oracle_attack" in categories("OracleLending")
    assert "delegatecall" in categories("UnsafeDelegate")
