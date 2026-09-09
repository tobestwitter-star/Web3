pragma solidity ^0.8.20;
interface IReceiver { function onTokenReceived(address from,uint256 amount) external; }
contract CallbackToken {
    mapping(address=>uint256) public balance;
    function mint(uint256 amount) external { balance[msg.sender] += amount; }
    function send(address to,uint256 amount) external {
        require(balance[msg.sender] >= amount, "balance");
        IReceiver(to).onTokenReceived(msg.sender, amount);
        balance[msg.sender] -= amount;
        balance[to] += amount;
    }
}
