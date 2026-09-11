// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {StateMachineVault, ReentrancyBank, UnreachableCandidate, InvariantPreserving, AuthorizationSequence, EconomicPool} from "../src/ProtocolFixtures.sol";

contract ItyFuzzDeployment {
    StateMachineVault public stateMachine;
    ReentrancyBank public reentrancy;
    UnreachableCandidate public unreachable;
    InvariantPreserving public invariantSafe;
    AuthorizationSequence public authorization;
    EconomicPool public economic;

    function setUp() public {
        stateMachine = new StateMachineVault();
        reentrancy = new ReentrancyBank();
        unreachable = new UnreachableCandidate();
        invariantSafe = new InvariantPreserving();
        authorization = new AuthorizationSequence();
        economic = new EconomicPool(1000, 1000);
    }
}
