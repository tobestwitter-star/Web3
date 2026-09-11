pragma solidity ^0.8.20;
contract InitializedProxy {
 address public owner; address public implementation; bool public initialized;
 function initialize(address newOwner,address impl) external { require(!initialized); initialized=true; owner=newOwner; implementation=impl; }
 function upgrade(address impl) external { require(msg.sender==owner); implementation=impl; }
}
