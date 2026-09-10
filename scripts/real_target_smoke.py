#!/usr/bin/env python3
"""Run the production research pipeline against a real, publicly scoped bounty target.

This is intentionally local-only: it clones an explicitly published public repository,
builds/tests it locally, runs the existing ResearchPipeline, and never contacts a live
contract or submits a report. The target is ENS's public Immunefi smart-contract bounty.
"""
from __future__ import annotations
import json, os, shutil, subprocess, sys, tempfile
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bounty_engine import PublicProgramDiscovery, Opportunity, score_opportunity
from research_pipeline import ResearchPipeline, STATUS

ENS_SCOPE = "https://immunefi.com/bug-bounty/ens/scope/"
ENS_INFO = "https://immunefi.com/bug-bounty/ens/information/"
ENS_REPO = "https://github.com/ensdomains/ens-contracts.git"
ENS_TAG = "v1.7.0"


def fetch(url: str) -> str:
    req = Request(url, headers={"User-Agent": "Web3-BugHunter/real-target-smoke"})
    with urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace")


def run(cmd, cwd=None, timeout=900):
    p = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, timeout=timeout)
    return {"returncode": p.returncode, "stdout": p.stdout[-12000:], "stderr": p.stderr[-12000:]}


def main():
    scope = fetch(ENS_SCOPE)
    info = fetch(ENS_INFO)
    if "Smart Contracts" not in scope or "Maximum Bounty" not in info:
        raise RuntimeError("ENS public scope evidence could not be verified")

    discovery = PublicProgramDiscovery()
    discovered, diagnostics = discovery.discover_public_indexes()
    ens = [x for x in discovered if x.name.lower().startswith("ens") and x.source.startswith("immunefi")]
    if not ens:
        ens_opp = Opportunity(
            id="immunefi:ens", source="immunefi", name="ENS", url=ENS_INFO, status="active",
            max_bounty_usd=250000.0, scope_size=10, source_code_available=True,
            competition_risk=.7, difficulty=.5, estimated_hours=24, severity_potential=1.0,
            likelihood=.65, attack_surface=["smart contracts", "name ownership", "resolution", "registrars"],
            scope_notes="Authoritative Immunefi scope page lists Smart Contracts and prohibits live/public-network testing; local forks are required.",
            metadata={"repositories":["https://github.com/ensdomains/ens-contracts"],"eligible_release":ENS_TAG,"scope_url":ENS_SCOPE,"rules_url":ENS_INFO},
        )
        ens_opp.score = score_opportunity(ens_opp)
    else:
        ens_opp = max(ens, key=lambda x: x.score)
        ens_opp.metadata = dict(ens_opp.metadata or {})
        ens_opp.metadata.update({"repositories":["https://github.com/ensdomains/ens-contracts"],"eligible_release":ENS_TAG,"scope_url":ENS_SCOPE,"rules_url":ENS_INFO})
        ens_opp.score = score_opportunity(ens_opp)

    with tempfile.TemporaryDirectory(prefix="web3-bughunter-real-") as td:
        repo = Path(td) / "ens-contracts"
        clone = run(["git", "clone", "--depth", "1", "--branch", ENS_TAG, ENS_REPO, str(repo)], timeout=300)
        if clone["returncode"]:
            raise RuntimeError(json.dumps({"stage":"acquisition","result":clone}))

        build = None
        if shutil.which("bun"):
            install = run(["bun", "install", "--frozen-lockfile"], cwd=repo, timeout=600)
            build = {"install": install}
            if install["returncode"] == 0:
                build["tests"] = run(["bun", "run", "test"], cwd=repo, timeout=900)
        else:
            build = {"skipped":"bun not installed"}

        sources=[]
        root=repo / "contracts"
        if root.is_dir():
            for p in root.rglob("*.sol"):
                if any(part in {"node_modules","lib","test","tests","mocks"} for part in p.parts):
                    continue
                try:
                    sources.append(f"// FILE: {p.relative_to(repo)}\n{p.read_text(encoding='utf-8',errors='replace')}")
                except OSError:
                    pass
        source_code="\n\n".join(sources)
        pipeline=ResearchPipeline()
        result=pipeline.analyze_local(
            str(repo), "ENS", source_code=source_code, authorization_confirmed=True,
            tools=["slither","aderyn","wake"],
            opportunity=ens_opp.to_dict() if hasattr(ens_opp,"to_dict") else ens_opp.__dict__,
        )

        out={
            "opportunity": ens_opp.to_dict() if hasattr(ens_opp,"to_dict") else ens_opp.__dict__,
            "public_scope_verified": True, "scope_url": ENS_SCOPE, "rules_url": ENS_INFO,
            "repository": ENS_REPO, "revision": ENS_TAG, "discovery_diagnostics": diagnostics,
            "acquisition": {"ok": True, "revision": ENS_TAG, "repository": ENS_REPO},
            "build": build, "pipeline": result, "finding_status": STATUS,
        }
        Path("real_target_result.json").write_text(json.dumps(out,indent=2,default=str),encoding="utf-8")
        print(json.dumps({
            "program": "ENS", "score": ens_opp.score, "source_files_analyzed": len(sources),
            "build": build,
            "tool_results": [{"name":r.get("name"),"skipped":r.get("skipped",False),"ok":r.get("result",{}).get("ok") if isinstance(r.get("result"),dict) else None} for r in result.get("tool_results",{}).get("results",[])],
            "finding_count": len(result.get("correlated_findings",[])), "review_status": STATUS,
        },indent=2))

if __name__ == "__main__": main()
