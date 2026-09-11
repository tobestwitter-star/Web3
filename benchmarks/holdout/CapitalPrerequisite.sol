pragma solidity ^0.8.20;
contract CapitalPrerequisite {
 uint256 public reserve; mapping(address=>uint256) public debt;
 function flashLoan(uint256 amount) external { require(amount<reserve); reserve-=amount; debt[msg.sender]+=amount; reserve+=amount; }
 function settle(uint256 amount) external { debt[msg.sender]-=amount; }
}
