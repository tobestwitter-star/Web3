pragma solidity ^0.8.20;
interface IOracle { function latest() external view returns(int256,uint256); }
contract StaleOracleDependency {
 IOracle public oracle; mapping(address=>uint256) public debt;
 function borrow(uint256 collateral) external { (int256 price,uint256 updated)=oracle.latest(); require(price>0); require(collateral*uint256(price)>=100 ether); debt[msg.sender]+=100 ether; }
}
