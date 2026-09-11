// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IntegrationFixture} from "../src/IntegrationFixture.sol";

contract IntegrationFixtureTest {
    uint256 private value;

    function testSetValue() public {
        value = 42;
        require(value == 42, "value not stored");
    }

    function check_setValue(uint256 x) public {
        value = x;
        assert(value == x);
    }
}
