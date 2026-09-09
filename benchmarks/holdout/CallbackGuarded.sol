pragma solidity ^0.8.20;
interface IReceiver { function onExit(address,uint256) external; }
contract CallbackGuarded {
 mapping(address=>uint256) public quota; uint256 private entered;
 function release(uint256 n) external {
   require(quota[msg.sender]>=n); quota[msg.sender]-=n;
   if (entered==0) { entered=1; IReceiver(msg.sender).onExit(msg.sender,n); entered=0; }
 }
}
