pragma solidity ^0.8.20;
contract BootState {
 enum Phase{Cold,Open,Closed} Phase public phase;
 address public governor; address public module;
 function bootstrap(address g,address m) external { governor=g; module=m; phase=Phase.Open; }
 function close() external { require(msg.sender==governor); phase=Phase.Closed; }
 function install(address m) external { require(msg.sender==governor); module=m; }
}
