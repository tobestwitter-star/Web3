pragma solidity ^0.8.20;
contract StateSafe {
 enum Mode{Idle,Live,Done} Mode public mode;
 address public governor;
 constructor(){governor=msg.sender;}
 function open() external { require(msg.sender==governor && mode==Mode.Idle); mode=Mode.Live; }
 function finish() external { require(msg.sender==governor && mode==Mode.Live); mode=Mode.Done; }
}
