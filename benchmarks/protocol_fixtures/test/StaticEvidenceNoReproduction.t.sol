// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import "../src/ProtocolFixtures.sol";
contract StaticEvidenceNoReproductionTest { function testStaticCandidateCannotReach() external { UnreachableCandidate c=new UnreachableCandidate(); bool ok; try c.suspicious(payable(address(1))){ok=true;}catch{} require(!ok,"security property violated"); } }
