pragma solidity ^0.8.20;
contract BootState {
 enum Phase{Cold,Open,Closed} Phase public phase;
 address public governor; address public implementation;
 function bootstrap(address g,address impl) external { governor=g; implementation=impl; phase=Phase.Open; }
 function close() external { require(msg.sender==governor); phase=Phase.Closed; }
 function install(address impl) external { require(msg.sender==governor); implementation=impl; }
}
