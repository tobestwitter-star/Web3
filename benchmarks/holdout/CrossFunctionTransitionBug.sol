pragma solidity ^0.8.20;
contract CrossFunctionTransitionBug {
 enum Phase { Idle, Prepared, Settled }
 Phase public phase;
 mapping(address=>uint256) public credit;
 function prepare() external { phase=Phase.Prepared; }
 function settle(address to,uint256 amount) external { require(phase==Phase.Prepared); credit[to]+=amount; phase=Phase.Settled; }
}
