pragma solidity ^0.8.20;
contract CapitalSafe {
 uint256 public reserve; mapping(address=>uint256) public debt;
 constructor(){reserve=1000;}
 function flashLoan(uint256 amount) external { require(amount<reserve); reserve-=amount; reserve+=amount; }
}
