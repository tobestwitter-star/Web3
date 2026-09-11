// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract HalmosCompatibleTest {
    uint256 internal phase;
    uint256 internal credit;

    function check_vulnerable_state_transition() public {
        phase = 1;
        if (phase == 1) {
            credit = 1;
        }
        assert(credit == 0);
    }

    function check_invariant_preserving() public {
        uint256 total = 100;
        uint256 balance = 60;
        uint256 recipient = 40;
        assert(balance + recipient == total);
    }

    function check_unreachable_precondition() public {
        uint256 phaseBefore = 0;
        uint256 requiredPhase = 2;
        if (phaseBefore == requiredPhase) {
            assert(false);
        }
        assert(phaseBefore != requiredPhase);
    }
}
