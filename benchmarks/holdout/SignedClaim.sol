pragma solidity ^0.8.20;
contract SignedClaim {
 mapping(address=>uint256) public paid;
 function redeem(address user,uint256 amount,uint8 v,bytes32 r,bytes32 s) external {
   address signer=ecrecover(keccak256(abi.encode(user,amount)),v,r,s);
   require(signer==user);
   paid[user]+=amount;
 }
}
