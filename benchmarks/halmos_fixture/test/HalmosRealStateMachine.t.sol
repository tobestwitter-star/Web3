// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @dev Halmos-compatible fixture: no deployCode/new or Foundry cheatcodes.
contract HalmosRealStateMachine {
    uint256 internal phase;
    uint256 internal credit;

    function check_vulnerable_state_transition() public {
        phase = 1;
        credit = 1;
        assert(credit == 0);
    }

    function check_safe_state_transition() public {
        phase = 1;
        credit = 1;
        assert(credit == 1);
    }

    function check_unreachable_transition() public {
        uint256 currentPhase = 0;
        uint256 requiredPhase = 2;
        if (currentPhase == requiredPhase) {
            assert(false);
        }
        assert(currentPhase != requiredPhase);
    }
}
