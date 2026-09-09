pragma solidity ^0.8.20;
interface IRegistry { function notify(address,uint256) external; }
contract CrossBoundary {
 IRegistry public registry; mapping(address=>uint256) public pending;
 function queue(uint256 n) external { require(pending[msg.sender]>=n); registry.notify(msg.sender,n); pending[msg.sender]-=n; }
}
