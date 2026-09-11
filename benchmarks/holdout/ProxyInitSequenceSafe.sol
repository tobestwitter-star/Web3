pragma solidity ^0.8.20;
contract ProxyInitSequenceSafe {
 address public immutable owner;
 address public implementation;
 bool public initialized;
 constructor(address admin,address impl){owner=admin;implementation=impl;initialized=true;}
 function initialize(address) external { require(!initialized); }
 function upgrade(address impl) external { require(msg.sender==owner); implementation=impl; }
}
