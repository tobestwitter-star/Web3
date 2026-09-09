pragma solidity ^0.8.20;
contract AccessControlVault {
    address public owner;
    mapping(address => uint256) public credits;
    constructor() { owner = msg.sender; }
    function mintCredit(address to, uint256 amount) external { credits[to] += amount; }
    function sweep(address payable to, uint256 amount) external { require(msg.sender == owner, "owner"); to.transfer(amount); }
    receive() external payable {}
}
