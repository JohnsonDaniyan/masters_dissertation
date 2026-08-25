from urllib.parse import unquote

from cryptography import x509

from app.registry.clients import cert_sha256_thumbprint, client_id_for_thumbprint


def normalize_cert_header(value: str) -> str:
    value = unquote(value).replace("\\n", "\n")
    if "BEGIN CERTIFICATE" in value:
        return value
    body = "".join(value.split())
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"


def validate_mtls(cert_header: str, client_id: str | None) -> str:
    pem = normalize_cert_header(cert_header)
    cert = x509.load_pem_x509_certificate(pem.encode())
    thumbprint = cert_sha256_thumbprint(cert)
    matched = client_id_for_thumbprint(thumbprint)
    if matched is None:
        raise ValueError("client certificate is not registered")
    if client_id and client_id != matched:
        raise ValueError("client_id does not match certificate")
    return matched
