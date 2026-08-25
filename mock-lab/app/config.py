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

settings = Settings()