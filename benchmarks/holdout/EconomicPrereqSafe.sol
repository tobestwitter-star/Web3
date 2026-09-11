pragma solidity ^0.8.20;
contract EconomicPrereqSafe {
 uint256 public reserve0=1000;
 uint256 public reserve1=1000;
 function settle(uint256 amount) external { require(amount>0 && amount<reserve1); reserve1-=amount; reserve0+=amount; }
}
