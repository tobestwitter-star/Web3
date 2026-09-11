pragma solidity ^0.8.20;
contract EconomicPrereqBug {
 uint256 public reserve0=1000;
 uint256 public reserve1=1000;
 function flashLoan(uint256 amount) external { reserve0-=amount; reserve1+=amount; }
 function settle(uint256 amount) external { reserve1-=amount; reserve0+=amount+1; }
}
