pragma solidity ^0.8.20;
contract SignatureSafe {
    mapping(address => uint256) public credits;
    mapping(address => uint256) public nonce;
    function permit(address user, uint256 amount, uint256 deadline, bytes32 digest, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= deadline, "expired");
        address signer = ecrecover(digest, v, r, s);
        require(signer == user, "bad signer");
        nonce[user] += 1;
        credits[user] += amount;
    }
}
