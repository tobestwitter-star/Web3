// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import "../src/ProtocolFixtures.sol";
contract HalmosSemanticTest {
    function checkStateMachineSecurityProperty() public {
        StateMachineVault v = new StateMachineVault();
        v.prepare();
        address other = address(0xBEEF);
        v.execute(other, 1);
        assert(v.credit(other) == 0);
    }
    function checkInvariantPreserving() public {
        InvariantPreserving s = new InvariantPreserving();
        s.mint(address(this), 100);
        uint256 beforeTotal = s.total();
        s.transfer(address(1), 40);
        assert(s.total() == beforeTotal);
    }
}
