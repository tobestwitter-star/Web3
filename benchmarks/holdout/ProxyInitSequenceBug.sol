pragma solidity ^0.8.20;
contract ProxyInitSequenceBug {
 address public owner;
 address public implementation;
 function initialize(address impl,address admin) external { implementation=impl; owner=admin; }
 function upgrade(address impl) external { implementation=impl; }
}
