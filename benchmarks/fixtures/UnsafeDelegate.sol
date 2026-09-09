pragma solidity ^0.8.20;
contract UnsafeDelegate {
    address public implementation;
    constructor(address impl) { implementation = impl; }
    function execute(bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory out) = implementation.delegatecall(data);
        require(ok, "delegate failed");
        return out;
    }
}
