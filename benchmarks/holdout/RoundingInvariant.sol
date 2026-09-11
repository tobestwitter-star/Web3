pragma solidity ^0.8.20;
contract RoundingInvariant {
 uint256 public totalShares; uint256 public assets;
 function mint(uint256 amount) external { uint256 shares=amount*totalShares/assets; totalShares+=shares; assets+=amount; }
}
