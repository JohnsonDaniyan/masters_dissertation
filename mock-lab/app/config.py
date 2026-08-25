import os
from dotenv import load_dotenv

load_dotenv()

print("meta shit"+ str(os.getenv("METADATA_ENABLED")))

class Settings:
    ISSUER: str = os.getenv("ISSUER", "https://mock-as.local")
    BASE_URL: str = os.getenv("BASE_URL", "https://mock-as.local")

    # Feature A toggles
    METADATA_ENABLED: bool = os.getenv("METADATA_ENABLED", "true").lower() == "true"
    METADATA_INCOMPLETE: bool = os.getenv("METADATA_INCOMPLETE", "false").lower() == "true"
    ISSUER_MISMATCH: bool = os.getenv("ISSUER_MISMATCH", "false").lower() == "true"
    ISSUER_MALFORMED: bool = os.getenv("ISSUER_MALFORMED", "false").lower() == "true"

    # Feature B toggles
    PAR_ENFORCED: bool = os.getenv("PAR_ENFORCED", "true").lower() == "true"
    REQUEST_URI_REUSABLE: bool = os.getenv("REQUEST_URI_REUSABLE", "false").lower() == "true"
    REQUEST_URI_LONG_LIVED: bool = os.getenv("REQUEST_URI_LONG_LIVED", "false").lower() == "true"
    ALLOW_PLAIN_PKCE: bool = os.getenv("ALLOW_PLAIN_PKCE", "false").lower() == "true"

    # Feature C toggles
    PKCE_ENFORCED: bool = os.getenv("PKCE_ENFORCED", "true").lower() == "true"

    # Feature D toggles
    JWT_REPLAY_PROTECTION: bool = os.getenv("JWT_REPLAY_PROTECTION", "true").lower() == "true"
    MTLS_CLIENT_AUTH_ENFORCED: bool = os.getenv("MTLS_CLIENT_AUTH_ENFORCED", "true").lower() == "true"
    ALLOW_WEAK_CLIENT_AUTH: bool = os.getenv("ALLOW_WEAK_CLIENT_AUTH", "false").lower() == "true"

    # Feature E toggles
    DPOP_VALIDATION_STRICT: bool = os.getenv("DPOP_VALIDATION_STRICT", "true").lower() == "true"
    DPOP_REPLAY_PROTECTION: bool = os.getenv("DPOP_REPLAY_PROTECTION", "true").lower() == "true"
    MTLS_BINDING_ENFORCED: bool = os.getenv("MTLS_BINDING_ENFORCED", "true").lower() == "true"

    # Feature F toggles
    TOKEN_UNSTRUCTURED: bool = os.getenv("TOKEN_UNSTRUCTURED", "false").lower() == "true"
    INTROSPECTION_AUTH_REQUIRED: bool = os.getenv("INTROSPECTION_AUTH_REQUIRED", "true").lower() == "true"
    RS_TRUSTS_AS_BLINDLY: bool = os.getenv("RS_TRUSTS_AS_BLINDLY", "false").lower() == "true"

settings = Settings()