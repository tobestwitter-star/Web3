// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IntegrationFixture} from "../src/IntegrationFixture.sol";

contract IntegrationFixtureTest {
    function testSetValue() public {
        IntegrationFixture target = new IntegrationFixture();
        target.setValue(42);
        require(target.value() == 42, "value not stored");
    }
}
