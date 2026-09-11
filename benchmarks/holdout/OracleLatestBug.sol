pragma solidity ^0.8.20;
interface ILatest { function latestPrice() external view returns(uint256,uint256); }
contract OracleLatestBug {
 ILatest public oracle; mapping(address=>uint256) public debt;
 function borrow(uint256 collateral) external { (uint256 price,uint256 updated)=oracle.latestPrice(); require(price>0); require(collateral*price>=100 ether); debt[msg.sender]+=100 ether; }
}
