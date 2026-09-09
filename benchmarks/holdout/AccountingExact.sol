pragma solidity ^0.8.20;
contract AccountingExact {
 mapping(address=>uint256) public units; uint256 public reserve;
 function add() external payable { units[msg.sender]+=msg.value; reserve+=msg.value; }
 function cashOut(uint256 u) external { require(units[msg.sender]>=u); units[msg.sender]-=u; reserve-=u; payable(msg.sender).transfer(u); }
}
