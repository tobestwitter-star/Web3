pragma solidity ^0.8.20;
contract CrossFunctionTransitionSafe {
 enum Phase { Idle, Prepared, Settled }
 Phase public phase;
 address public governor;
 mapping(address=>uint256) public credit;
 constructor(){governor=msg.sender;}
 function prepare() external { require(msg.sender==governor && phase==Phase.Idle); phase=Phase.Prepared; }
 function settle(address to,uint256 amount) external { require(msg.sender==governor && phase==Phase.Prepared); credit[to]+=amount; phase=Phase.Settled; }
}
