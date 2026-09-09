pragma solidity ^0.8.20;
contract StateMachine {
    enum State { Open, Settled, Cancelled }
    State public state;
    mapping(address => uint256) public deposits;
    function deposit() external payable { require(state == State.Open, "closed"); deposits[msg.sender] += msg.value; }
    function settle() external { state = State.Settled; }
    function cancel() external { require(state == State.Open, "not open"); state = State.Cancelled; }
    receive() external payable {}
}
