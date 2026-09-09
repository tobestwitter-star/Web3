pragma solidity ^0.8.20;
contract InitializerSafe {
    address public owner;
    bool public initialized;
    function initialize(address newOwner) external {
        require(!initialized, "initialized");
        initialized = true;
        owner = newOwner;
    }
    function upgrade(address implementation) external {
        require(msg.sender == owner, "owner");
        implementation;
    }
}
