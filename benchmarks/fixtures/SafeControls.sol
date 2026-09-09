pragma solidity ^0.8.20;
contract SafeControls {
    address public immutable owner;
    mapping(address=>uint256) public balance;
    uint256 public total;
    constructor() { owner = msg.sender; }
    function deposit() external payable { balance[msg.sender] += msg.value; total += msg.value; }
    function withdraw(uint256 amount) external {
        require(balance[msg.sender] >= amount, "balance");
        balance[msg.sender] -= amount;
        total -= amount;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "send");
    }
    function sweep(address payable to,uint256 amount) external { require(msg.sender == owner, "owner"); to.transfer(amount); }
    receive() external payable {}
}
