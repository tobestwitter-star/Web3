pragma solidity ^0.8.20;
contract ReentrancySafe {
    mapping(address => uint256) public balances;
    bool private locked;
    modifier nonReentrant() { require(!locked, "locked"); locked = true; _; locked = false; }
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external nonReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "empty");
        balances[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }
    receive() external payable {}
}
