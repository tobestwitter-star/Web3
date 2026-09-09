pragma solidity ^0.8.20;
contract RateVault {
 mapping(address=>uint256) public units; uint256 public reserve;
 function add() external payable { units[msg.sender]+=msg.value; reserve+=msg.value; }
 function cashOut(uint256 u) external { require(units[msg.sender]>=u); units[msg.sender]-=u; uint256 payout=u*1001/1000; payable(msg.sender).transfer(payout); reserve-=payout; }
}
