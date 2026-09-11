pragma solidity ^0.8.20;
contract CrossFunctionState {
 uint256 public status; uint256 public credit;
 function prepare() external { status=1; }
 function execute(uint256 amount) external { require(status==1); credit+=amount; status=2; }
}
