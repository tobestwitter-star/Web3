// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IntegrationFixture} from "../src/IntegrationFixture.sol";

contract ItyFuzzDeployment {
    IntegrationFixture public target;

    function setUp() public {
        target = new IntegrationFixture();
    }
}
