pragma solidity ^0.8.20;
contract PrecisionSafe {
 uint256 public total; mapping(address=>uint256) public shares;
 function deposit(uint256 amount) external { uint256 s=amount*1e18/1e18; shares[msg.sender]+=s; total+=s; }
 function redeem(uint256 s) external { require(shares[msg.sender]>=s); shares[msg.sender]-=s; total-=s; payable(msg.sender).transfer(s); }
}
