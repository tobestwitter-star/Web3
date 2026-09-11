// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import "../src/ProtocolFixtures.sol";
interface Vm { function deal(address,uint256) external; function prank(address) external; function expectRevert(string calldata) external; }
contract ProtocolFixturesTest {
 Vm constant vm=Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
 function testMultiStepStateMachineReproduction() public { StateMachineVault v=new StateMachineVault(); v.prepare(); v.execute(address(this),1 ether); require(v.credit(address(this))==1 ether,"security property violated"); }
 function testReentrancySequenceReproduction() public { ReentrancyBank b=new ReentrancyBank(); ReentrancyAttacker a=new ReentrancyAttacker(b); vm.deal(address(a),1 ether); vm.prank(address(a)); a.attack(); require(a.reentries()==1,"security property violated"); }
 function testUnreachableCandidateIsSafe() public { UnreachableCandidate c=new UnreachableCandidate(); bool ok; try c.suspicious(){ok=true;}catch{} require(!ok,"security property violated"); }
 function testInvariantPreservingCandidate() public { InvariantPreserving s=new InvariantPreserving(); s.mint(address(this),100); uint256 beforeTotal=s.total(); s.transfer(address(1),40); require(s.total()==beforeTotal,"security property violated"); }
 function testAuthorizationRequiresSpecificTransition() public { AuthorizationSequence a=new AuthorizationSequence(); vm.expectRevert("operator"); a.execute(10); a.queueOperator(address(this)); a.execute(10); require(a.credit(address(this))==10,"security property violated"); }
 function testEconomicStateDependentReproduction() public { EconomicPool p=new EconomicPool(1000,1000); uint256 before0=p.reserve0(); uint256 before1=p.reserve1(); uint256 out=p.swap(100); require(out>0,"security property violated"); require(p.reserve0()*p.reserve1()!=before0*before1,"security property violated"); }
}
