pragma solidity ^0.8.20;
contract SignatureReplay {
    mapping(address => uint256) public credits;
    function claim(address user, uint256 amount, bytes32 digest, uint8 v, bytes32 r, bytes32 s) external {
        address signer = ecrecover(digest, v, r, s);
        require(signer == user, "bad signer");
        credits[user] += amount;
    }
}
