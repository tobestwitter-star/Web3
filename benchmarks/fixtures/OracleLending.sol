pragma solidity ^0.8.20;
interface IOracle { function getPrice() external view returns(uint256); }
contract OracleLending {
    IOracle public oracle;
    mapping(address => uint256) public debt;
    constructor(address o) { oracle = IOracle(o); }
    function borrow(uint256 collateral) external { uint256 price = oracle.getPrice(); require(collateral * price >= 100 ether, "collateral"); debt[msg.sender] += 100 ether; }
}
