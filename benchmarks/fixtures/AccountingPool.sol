pragma solidity ^0.8.20;
contract AccountingPool {
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    function deposit() external payable { shares[msg.sender] += msg.value; totalShares += msg.value; }
    function withdraw(uint256 amount) external { require(shares[msg.sender] >= amount, "shares"); shares[msg.sender] -= amount; totalShares -= amount; payable(msg.sender).transfer(amount + 1); }
    receive() external payable {}
}
