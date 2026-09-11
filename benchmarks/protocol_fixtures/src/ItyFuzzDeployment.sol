// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import "./ProtocolFixtures.sol";
contract ItyFuzzDeployment {
    function deployAll() external {
        new StateMachineVault();
        new ReentrancyBank();
        new UnreachableCandidate();
        new InvariantPreserving();
        new AuthorizationSequence();
        new EconomicPool(1000, 1000);
    }
}
