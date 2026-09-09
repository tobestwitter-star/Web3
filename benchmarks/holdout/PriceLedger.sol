pragma solidity ^0.8.20;
interface IPrice { function read() external view returns(uint256); }
contract PriceLedger {
 IPrice public feed; mapping(address=>uint256) public debt; uint256 public cash;
 function deposit() external payable { cash += msg.value; }
 function borrow(uint256 units) external { uint256 p=feed.read(); uint256 value=units*p; require(value<cash); debt[msg.sender]+=value; cash-=value+1; payable(msg.sender).transfer(value); }
}
