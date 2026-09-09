pragma solidity ^0.8.20;
interface IFeed { function latestRoundData() external view returns(uint80,int256,uint256,uint256,uint80); }
contract OracleGuarded {
 IFeed public feed; mapping(address=>uint256) public debt;
 function borrow(uint256 collateral) external { (uint80 round,int256 answer,,uint256 updated,uint80 answered)=feed.latestRoundData(); require(answer>0 && answered==round); require(block.timestamp-updated<1 hours); require(collateral*uint256(answer)>=100 ether); debt[msg.sender]+=100 ether; }
}
