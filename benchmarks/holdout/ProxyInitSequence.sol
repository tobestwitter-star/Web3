pragma solidity ^0.8.20;
contract ProxyInitSequence {
 address public owner; address public implementation;
 function initialize(address newOwner,address impl) external { owner=newOwner; implementation=impl; }
 function upgrade(address impl) external { require(msg.sender==owner); implementation=impl; }
}
