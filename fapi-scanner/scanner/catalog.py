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
]
