pragma solidity ^0.8.20;
contract ProxyBoundary {
 bytes32 internal constant SLOT=keccak256("impl");
 function setImplementation(address target) external { assembly { sstore(SLOT,target) } }
 function forward(bytes calldata data) external payable returns(bytes memory out) {
   address target; assembly { target := sload(SLOT) }
   (bool ok,bytes memory ret)=target.delegatecall(data); require(ok); return ret;
 }
}
