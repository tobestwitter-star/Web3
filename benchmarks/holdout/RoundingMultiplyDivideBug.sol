pragma solidity ^0.8.20;
contract RoundingMultiplyDivideBug {
 uint256 public totalShares=3; uint256 public assets=10;
 mapping(address=>uint256) public shares;
 function mint(uint256 amount) external { uint256 s=amount*totalShares/assets; shares[msg.sender]+=s; totalShares+=s; assets+=amount; }
}
