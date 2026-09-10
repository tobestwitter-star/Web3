from evidence_attribution import SourceAttributor

def test_attribution_does_not_jump_to_later_function():
    code='''// FILE: contracts/Vault.sol\ncontract Vault {\n    function withdraw(uint amount) external {\n        target.call{value: amount}("");\n        balances[msg.sender] -= amount;\n    }\n    function supportsInterface(bytes4 id) external pure returns (bool) {\n        return id == 0x01ffc9a7;\n    }\n    function ownerOf(uint id) external view returns (address) {\n        return address(0);\n    }\n}\n'''
    a=SourceAttributor(code)
    pos=code.index('target.call')
    ctx=a.context_at(pos)
    assert ctx.file == 'contracts/Vault.sol'
    assert ctx.contract == 'Vault'
    assert ctx.function == 'withdraw'
    assert ctx.function != 'supportsInterface'
    assert ctx.function != 'ownerOf'
    assert ctx.certainty == 'exact'

def test_unknown_position_is_explicitly_uncertain():
    a=SourceAttributor('contract A { function one() external {} }')
    out=a.attribute({'title':'candidate','location':'unknown','evidence':['not present']})
    assert out['location_uncertain'] is True
    assert out['attribution_status'] == 'uncertain'
