pragma solidity ^0.8.20;
contract AccessControlSafe {
    address public owner;
    mapping(address => uint256) public credits;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }
    function mintCredit(address to, uint256 amount) external onlyOwner { credits[to] += amount; }
    function sweep(address payable to, uint256 amount) external onlyOwner { to.transfer(amount); }
    receive() external payable {}
}
