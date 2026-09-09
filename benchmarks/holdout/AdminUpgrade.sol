pragma solidity ^0.8.20;
contract AdminUpgrade {
 address public controller; address public logic;
 function promote(address x) external { controller=x; }
 function rotate(address next) external { logic=next; }
 function mintCredit(address who,uint256 n) external { assembly { sstore(who,n) } }
}
