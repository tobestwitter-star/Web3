import tempfile
from pathlib import Path
from target_resolution import ScopeResolver,BuildDetector,TargetMap

def test_scope_resolver_maps_multiple_repos_and_contracts():
    op={'id':'x','name':'Demo','source':'immunefi','url':'https://example.test','metadata':{'repositories':['https://github.com/acme/core','https://github.com/acme/periphery'],'assets':['0x1111111111111111111111111111111111111111'],'out_of_scope':['frontend'],'rules':'No mainnet testing'}}
    s=ScopeResolver().resolve(op,'In-scope deployment 0x2222222222222222222222222222222222222222')
    assert len(s['repositories'])==2
    assert '0x2222222222222222222222222222222222222222' in s['contract_addresses']
    assert 'frontend' in s['exclusions']

def test_build_detector_hardhat():
    with tempfile.TemporaryDirectory() as td:
        p=Path(td);(p/'hardhat.config.ts').write_text('');(p/'package.json').write_text('{"devDependencies":{"hardhat":"^2"}}');(p/'X.sol').write_text('contract X {}')
        d=BuildDetector().detect(td)
        assert d['primary']=='hardhat' and d['solidity_files']==1

def test_target_map_preserves_scope_and_build():
    s={'program':'Demo','targets':[{'kind':'repository','identifier':'r'}],'repositories':['r'],'contract_addresses':['0x1'],'assets':['a'],'exclusions':['x'],'rules':'rules'}
    b={'primary':'foundry','detected':[{'system':'foundry'}]}
    m=TargetMap().build(s,b)
    assert m['complete_map'] is True and m['build']['primary']=='foundry' and m['exclusions']==['x']
