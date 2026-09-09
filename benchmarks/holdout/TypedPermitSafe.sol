pragma solidity ^0.8.20;
contract TypedPermitSafe {
 mapping(address=>uint256) public nonce; mapping(address=>uint256) public credit; bytes32 public immutable DOMAIN_SEPARATOR;
 constructor(){ DOMAIN_SEPARATOR=keccak256(abi.encode(block.chainid,address(this))); }
 function approveBySig(address who,uint256 n,uint256 expiry,uint8 v,bytes32 r,bytes32 s) external { require(block.timestamp<=expiry); bytes32 d=keccak256(abi.encode(DOMAIN_SEPARATOR,who,n,nonce[who],expiry)); require(ecrecover(d,v,r,s)==who); nonce[who]++; credit[who]=n; }
}
