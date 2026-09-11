pragma solidity ^0.8.20;
interface IAuthorityBug { function approved(address) external view returns(bool); }
contract CrossContractTrustBug {
 IAuthorityBug public authority; mapping(address=>uint256) public credit;
 constructor(IAuthorityBug a){authority=a;}
 function execute(uint256 amount) external { credit[msg.sender]+=amount; }
 function authorityCheck(address user) external view returns(bool) { return authority.approved(user); }
}
