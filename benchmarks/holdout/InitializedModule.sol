pragma solidity ^0.8.20;
contract InitializedModule {
 bool private ready; address public operator; address public implementation;
 modifier once(){ require(!ready); ready=true; _; }
 function setup(address op,address impl) external once { operator=op; implementation=impl; }
 function change(address impl) external { require(msg.sender==operator); implementation=impl; }
}
