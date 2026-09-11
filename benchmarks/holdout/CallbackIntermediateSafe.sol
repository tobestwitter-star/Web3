pragma solidity ^0.8.20;
contract CallbackIntermediateSafe {
 uint256 public status; mapping(address=>uint256) public credit;
 function onTokenReceived(address user,uint256 amount) external { require(status==1); credit[user]+=amount; status=2; }
 function open() external { status=1; }
}
