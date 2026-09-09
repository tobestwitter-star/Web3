pragma solidity ^0.8.20;
contract RoundingLoss {
 mapping(address=>uint256) public shares;
 function mint(uint256 amount) external { shares[msg.sender] += amount / 3; }
 function redeem(uint256 n) external { require(shares[msg.sender]>=n); shares[msg.sender]-=n; }
}
