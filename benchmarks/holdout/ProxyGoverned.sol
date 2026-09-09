pragma solidity ^0.8.20;
contract ProxyGoverned {
 address public admin; address public implementation;
 constructor(address a,address i){admin=a;implementation=i;}
 modifier onlyAdmin(){require(msg.sender==admin);_;}
 function upgradeTo(address next) external onlyAdmin { implementation=next; }
 function run(address next,bytes calldata data) external onlyAdmin returns(bool){ (bool ok,)=next.delegatecall(data); return ok; }
}
