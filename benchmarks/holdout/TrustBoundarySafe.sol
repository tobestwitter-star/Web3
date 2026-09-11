pragma solidity ^0.8.20;
contract TrustBoundarySafe {
 address public immutable authority;
 mapping(address=>uint256) public credit;
 constructor(address a){authority=a;}
 function mint(uint256 amount) external { require(msg.sender==authority); credit[msg.sender]+=amount; }
}
