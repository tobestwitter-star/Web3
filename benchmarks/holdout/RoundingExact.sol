pragma solidity ^0.8.20;
contract RoundingExact {
 uint256 public totalShares=1000; uint256 public assets=1000;
 function preview(uint256 amount) external view returns(uint256) { return amount*totalShares/assets; }
}
