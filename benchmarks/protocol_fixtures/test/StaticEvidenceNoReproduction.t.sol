// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
contract StaticEvidenceNoReproductionTest { uint256 public state; function suspicious() external { require(state==type(uint256).max,"unreachable state"); state=0; } function testStaticCandidateCannotReach() external { bool ok; try this.suspicious(){ok=true;}catch{} require(!ok,"security property violated"); } }
