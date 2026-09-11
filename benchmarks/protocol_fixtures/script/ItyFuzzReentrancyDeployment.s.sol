// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {ReentrancyBank, ReentrancyAttacker} from "../src/ProtocolFixtures.sol";

contract ItyFuzzReentrancyDeployment {
    ReentrancyBank public bank;
    ReentrancyAttacker public attacker;

    function setUp() public {
        bank = new ReentrancyBank();
        attacker = new ReentrancyAttacker(bank);
    }
}
