import os
import tempfile
from security_toolchain import SecurityToolchain

def test_inventory_is_non_destructive():
    tools = SecurityToolchain().inventory()
    assert {t['name'] for t in tools} == {'slither','aderyn','forge','echidna'}
    assert all('license' in t and 'project' in t for t in tools)

def test_analysis_requires_local_directory():
    result = SecurityToolchain().analyze('/definitely/not/a/real/path')
    assert result['authorized_local_analysis_only'] is True
    assert all(r.get('result',{}).get('error') == 'source directory does not exist' for r in result['results'] if 'result' in r)
