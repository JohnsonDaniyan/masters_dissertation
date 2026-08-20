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

settings = Settings()