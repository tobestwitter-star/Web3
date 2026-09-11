pragma solidity ^0.8.20;
interface IAuthority { function approved(address) external view returns(bool); }
contract TrustBoundaryBug {
 IAuthority public authority;
 mapping(address=>uint256) public credit;
 function mint(uint256 amount) external { require(authority.approved(msg.sender)); credit[msg.sender]+=amount; }
}
