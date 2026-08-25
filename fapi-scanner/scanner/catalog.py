CHECKS = [
    {
        "check_id": "DISC-001",
        "title": "AS metadata reachability",
        "description": "Verifies the authorisation server publishes a reachable RFC 8414 metadata document.",
        "reference": "Hosseyni et al. (2025) — attacker token injection / client impersonation precondition.",
    },
    {
        "check_id": "DISC-002",
        "title": "Issuer identifier format",
        "description": "Checks that the metadata issuer is an HTTPS URL with no query string or fragment.",
        "reference": "RFC 9207 / FAPI 2.0 Security Profile — issuer identification.",
    },
    {
        "check_id": "DISC-003",
        "title": "PAR advertisement",
        "description": "Confirms pushed authorisation requests are advertised as required by FAPI 2.0.",
        "reference": "RFC 9126 PAR; FAPI 2.0 require_pushed_authorization_requests.",
    },
    {
        "check_id": "PAR-001",
        "title": "PAR parameter validation",
        "description": "Checks that POST /par rejects missing or invalid parameters and issues a request_uri for a well-formed request.",
        "reference": "RFC 9126 Pushed Authorization Requests; FAPI 2.0 Security Profile.",
    },
    {
        "check_id": "PAR-002",
        "title": "Authorization requires request_uri",
        "description": "Verifies GET /authorize rejects front-channel parameters and unknown request_uri values, and accepts a freshly issued request_uri.",
        "reference": "RFC 9126 Pushed Authorization Requests; FAPI 2.0 require_pushed_authorization_requests.",
    },
    {
        "check_id": "PAR-003",
        "title": "request_uri is single-use",
        "description": "Confirms that a request_uri cannot be replayed at the authorization endpoint.",
        "reference": "RFC 9126 §2.2 — request_uri must be single-use unless explicitly advertised otherwise.",
    },
]
