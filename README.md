# Web3 BugHunter

Web3 BugHunter is an authorized Web3 security research platform built from the user's existing project foundation.

## Research workflow

**Discover → Evaluate → Rank → Select → Investigate → Validate → Generate Report → Human Review → Manual Submission**

The platform discovers public bounty feeds, scores opportunities by expected research value, maintains hunting history, analyzes authorized code, and produces structured reports.

### Safety / submission gate

Findings are always marked **UNVERIFIED — HUMAN REVIEW REQUIRED**. The system never submits bounty reports automatically. A researcher must verify scope, reproduce the issue, assess impact, check duplicates, edit the report, and manually submit.

## Backend

- `advanced_web3_analyzer.py` — existing advanced analyzer, preserved and hardened with an API-key-optional report fallback.
- `bounty_engine.py` — opportunity discovery, expected-value scoring, persistence, hunt status tracking, and human-review report packaging.
- `main.py` — Flask API exposing discovery, ranking, selection, analysis, history, and report endpoints.

## Local run

```bash
python -m pip install -r requirements.txt
python main.py
```

The SQLite database is created locally and is ignored by Git.

## Public repository safety

Secrets must be supplied through environment variables and must never be committed. The project intentionally contains no real credentials or API keys.

## Scope

Only explicitly authorized bug-bounty targets may be tested. Public program discovery is metadata discovery; a reachable program feed is not by itself proof that a target is in scope.
