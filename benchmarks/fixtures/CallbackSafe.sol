pragma solidity ^0.8.20;
interface IReceiverSafe { function onTokenReceived(address from,uint256 amount) external; }
contract CallbackSafe {
    mapping(address=>uint256) public balance;
    function mint(uint256 amount) external { balance[msg.sender] += amount; }
    function send(address to,uint256 amount) external {
        require(balance[msg.sender] >= amount, "balance");
        balance[msg.sender] -= amount;
        balance[to] += amount;
        IReceiverSafe(to).onTokenReceived(msg.sender, amount);
    }
}
