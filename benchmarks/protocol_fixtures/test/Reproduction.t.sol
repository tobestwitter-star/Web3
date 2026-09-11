// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import "../src/ProtocolFixtures.sol";
interface Vm { function deal(address,uint256) external; function prank(address) external; }
contract ReproductionTest {
 Vm constant vm=Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
 function testStateMachineSecurityProperty() public { StateMachineVault v=new StateMachineVault(); v.prepare(); v.execute(address(this),1 ether); require(false,"security property violated: execute reachable without authorized preparer"); }
 function testReentrancySecurityProperty() public { ReentrancyBank b=new ReentrancyBank(); ReentrancyAttacker a=new ReentrancyAttacker(b); vm.deal(address(this),1 ether); b.deposit{value:1 ether}(); vm.deal(address(a),1 ether); vm.prank(address(a)); a.attack(); require(address(b).balance>=1 ether,"security property violated: reentrant withdrawal drained seeded liquidity"); }
 function testEconomicSecurityProperty() public { EconomicPool p=new EconomicPool(1000,1000); uint256 beforeProduct=p.reserve0()*p.reserve1(); p.swap(100); require(p.reserve0()*p.reserve1()==beforeProduct,"security property violated: economic invariant changed"); }
}
