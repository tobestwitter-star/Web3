pragma solidity ^0.8.20;
abstract contract Roles { address internal chief; modifier gate(){ require(msg.sender==chief); _; } constructor(){chief=msg.sender;} }
contract RoleInherited is Roles {
 mapping(address=>uint256) public score;
 function grant(address a,uint256 n) external gate { score[a]=n; }
 function publicMint(uint256 n) external { score[msg.sender]+=n; }
}
