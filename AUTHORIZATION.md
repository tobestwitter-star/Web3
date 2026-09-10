# Backend authorization

Protected research operations require a backend-controlled authorization record. Public discovery, published scope evidence, and Android user acknowledgement are not authorization.

The backend reads `BUGHUNTER_AUTHORIZATION_RECORDS` from its server environment. The value is a JSON object keyed by the canonical opportunity id, for example:

```json
{
  "opportunities": {
    "immunefi:example": {
      "verified": true,
      "verified_by": "authorized-program-reviewer",
      "basis": "Explicit program authorization record"
    }
  }
}
```

The Android client cannot create or alter this record. Protected endpoints resolve the opportunity from the backend store and verify the server-side record before research, acquisition, fuzzing, economic analysis, or advanced analysis.

If no record exists, the backend fails closed and returns HTTP 403. The Android client displays the public scope evidence but does not enable the authorization confirmation control or protected research actions.

This mechanism does not bypass authentication, CAPTCHA, rate limits, anti-bot systems, or access controls, and findings remain `UNVERIFIED — HUMAN REVIEW REQUIRED`.
