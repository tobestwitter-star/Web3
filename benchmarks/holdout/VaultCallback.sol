pragma solidity ^0.8.20;
interface IHook { function onExit(address,uint256) external; }
contract VaultCallback {
 mapping(address=>uint256) internal credits;
 IHook public hook;
 function leave(uint256 q) external {
   require(credits[msg.sender] >= q);
   (bool ok,) = address(hook).call(abi.encodeWithSelector(IHook.onExit.selector,msg.sender,q));
   require(ok);
   credits[msg.sender] = credits[msg.sender] - q;
 }
 function fund() external payable { credits[msg.sender] += msg.value; }
}
