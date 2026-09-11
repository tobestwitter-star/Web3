pragma solidity ^0.8.20;
contract UnreachableEconomicPath {
 uint256 public state;
 function suspicious(uint256 amount) external { require(state==type(uint256).max); if(amount>0){ state=amount; } }
}
