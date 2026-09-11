// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import "./ProtocolFixtures.sol";

contract ItyFuzzDeployment {
    StateMachineVault public stateMachine;
    ReentrancyBank public bank;
    UnreachableCandidate public unreachable;
    InvariantPreserving public invariantPreserving;
    AuthorizationSequence public authorization;
    EconomicPool public economic;

    function setUp() public {
        stateMachine = new StateMachineVault();
        bank = new ReentrancyBank();
        unreachable = new UnreachableCandidate();
        invariantPreserving = new InvariantPreserving();
        authorization = new AuthorizationSequence();
        economic = new EconomicPool(1000, 1000);
    }
}
