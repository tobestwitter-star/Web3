pragma solidity ^0.8.20;
contract InitializerBug {
    address public owner;
    bool public initialized;
    function initialize(address newOwner) external { owner = newOwner; initialized = true; }
    function upgrade(address implementation) external { require(msg.sender == owner, "owner"); implementation; }
}
