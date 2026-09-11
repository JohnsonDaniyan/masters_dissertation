# Lab configuration toggles

This table is the running map from mock Open Banking lab toggles to the
scanner check that detects the matching non-conformance. Defaults are the
**conformant** setting. For each row, run the check against both toggle
states to collect detection-accuracy data.

| Feature | Toggle | Default | Check ID | Attack tested |
|---|---|---|---|---|
| A | `METADATA_ENABLED` | `true` | `DISC-001` | Token endpoint misconfiguration precondition |
| A | `METADATA_INCOMPLETE` | `false` | `DISC-003` | Incomplete discovery document / missing PAR advertisement |
| A | `ISSUER_MISMATCH` | `false` | `RESP-001` | Mix-up (issuer) — tested at Feature G, sourced at A |
| A | `ISSUER_MALFORMED` | `false` | `DISC-002` | Issuer identifier format violation (RFC 9207 / FAPI 2.0) |
| B | `PAR_ENFORCED` | `true` | `PAR-001` | PAR bypass |
| B | `REQUEST_URI_REUSABLE` | `false` | `PAR-002` | `request_uri` replay |
| C | `PKCE_ENFORCED` | `true` | `PKCE-001` | PKCE downgrade / code interception |
| C | `ALLOW_PLAIN_PKCE` | `false` | `PKCE-002` | Weak PKCE method |
| D | `JWT_REPLAY_PROTECTION` | `true` | `AUTH-001` | Client assertion replay |
| D | `MTLS_CLIENT_AUTH_ENFORCED` | `true` | `AUTH-002` | Client impersonation |
| D | `ALLOW_WEAK_CLIENT_AUTH` | `false` | `AUTH-003` | Weak client auth downgrade |
| E | `DPOP_REPLAY_PROTECTION` | `true` | `DPOP-001` | DPoP Proof Replay (Hosseyni et al., §3.3) |
| E | `DPOP_VALIDATION_STRICT` | `true` | `DPOP-002` | Malformed proof acceptance |
| E | `MTLS_BINDING_ENFORCED` | `true` | `MTLS-002` | Token binding bypass |
| F | `INTROSPECTION_AUTH_REQUIRED` | `true` | `TOK-001` | Unauthenticated introspection |
| F | `RS_TRUSTS_AS_BLINDLY` | `false` | `TOK-002` | Cuckoo's Token Attack (§3.5) |
| G | `ISS_PARAM_OMITTED` | `false` | `RESP-001` | Mix-up / issuer verification |
| G | `REDIRECT_URI_LOOSE_MATCH` | `false` | `RESP-002` | Redirect URI manipulation |
| G | `JARM_SIGNATURE_CHECK` | `true` | `RESP-003` | Unsigned/invalid JARM response |
| H | `DCR_OPEN_REGISTRATION` | `false` | `DCR-001` | Unauthorised client registration |
| H | `DCM_AUTH_REQUIRED` | `true` | `DCM-001` | Unauthenticated client config update |

Related non-toggle lab setting: `INITIAL_ACCESS_TOKEN` (default `lab-initial-access-token`) is the bearer token the scanner uses for legitimate DCR during a baseline flow.

**REQUEST_URI_LONG_LIVED**