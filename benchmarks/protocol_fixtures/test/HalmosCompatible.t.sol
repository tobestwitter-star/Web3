// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// @dev Deliberately avoids contract deployment and Foundry cheatcodes. This is
/// the Halmos-compatible equivalent of the deployCode/new-based fixtures.
contract HalmosStateMachine {
    uint256 public phase;
    uint256 public credit;

    function prepare() internal {
        phase = 1;
    }

    function execute(uint256 amount) internal {
        require(phase == 1, "not prepared");
        credit += amount;
        phase = 2;
    }
}

contract HalmosCompatibleTest is HalmosStateMachine {
    function check_vulnerable_state_transition() public {
        prepare();
        execute(1);
        assert(credit == 0);
    }

    function check_invariant_preserving_transfer() public {
        uint256 total = 100;
        uint256 balance = 100;
        uint256 amount = 40;
        balance -= amount;
        uint256 recipient = amount;
        assert(balance + recipient == total);
    }

    function check_unreachable_transition() public {
        uint256 requiredPhase = 2;
        uint256 currentPhase = 0;
        if (currentPhase == requiredPhase) {
            assert(false);
        }
        assert(currentPhase != requiredPhase);
    }
}
