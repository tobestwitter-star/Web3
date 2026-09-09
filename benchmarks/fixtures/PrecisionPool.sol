pragma solidity ^0.8.20;
contract PrecisionPool {
    uint256 public total;
    mapping(address => uint256) public balance;
    function deposit(uint256 amount) external { uint256 shares = amount / 1e18; balance[msg.sender] += shares; total += shares; }
    function redeem(uint256 shares) external { require(balance[msg.sender] >= shares, "shares"); balance[msg.sender] -= shares; total -= shares; payable(msg.sender).transfer(shares * 1e18); }
    receive() external payable {}
}
