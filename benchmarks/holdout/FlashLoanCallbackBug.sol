pragma solidity ^0.8.20;
interface IBorrower { function onLoan(uint256 amount) external; }
contract FlashLoanCallbackBug {
 uint256 public reserve=1000;
 function flashLoan(address borrower,uint256 amount) external { require(amount<=reserve); reserve-=amount; IBorrower(borrower).onLoan(amount); reserve+=amount; }
}
