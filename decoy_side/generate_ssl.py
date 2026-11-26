import datetime
import ipaddress
import os
import socket
import subprocess
from typing import Iterable, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _detect_local_ip() -> Optional[str]:
    """Detect primary non-loopback LAN IPv4 address when network routing is available."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            ip_val = sock.getsockname()[0]
            if ip_val and ip_val not in ("0.0.0.0", "127.0.0.1"):
                return ip_val
    except OSError:
        return None
    return None


def _build_san_entries(extra_sans: Optional[Iterable[str]] = None) -> List[x509.GeneralName]:
    """Build deduplicated Subject Alternative Name DNS/IP entries from deployment config."""
    candidates: List[str] = ["localhost", "127.0.0.1", "::1"]

    for env_key in ("BAITSCOPE_TLS_COMMON_NAME", "BAITSCOPE_DECOY_HOST", "SENTINEL_DECOY_HOST"):
        val = (os.getenv(env_key) or "").strip()
        if val and val not in ("0.0.0.0", "::", "*"):
            candidates.append(val)

    env_sans = os.getenv("BAITSCOPE_TLS_SANS") or os.getenv("SENTINEL_TLS_SANS") or ""
    for item in env_sans.split(","):
        cleaned = item.strip()
        if cleaned:
            candidates.append(cleaned)

    if extra_sans:
        for item in extra_sans:
            cleaned = str(item).strip()
            if cleaned:
                candidates.append(cleaned)

    local_ip = _detect_local_ip()
    if local_ip:
        candidates.append(local_ip)

    hostname = socket.gethostname().strip()
    if hostname and hostname not in ("0.0.0.0", "::"):
        candidates.append(hostname)

    entries: List[x509.GeneralName] = []
    seen = set()
    for candidate in candidates:
        try:
            ip_obj = ipaddress.ip_address(candidate)
            key = ("ip", ip_obj.compressed)
            if key not in seen:
                seen.add(key)
                entries.append(x509.IPAddress(ip_obj))
        except ValueError:
            dns_name = candidate.lower()
            key = ("dns", dns_name)
            if key not in seen:
                seen.add(key)
                entries.append(x509.DNSName(dns_name))
    return entries


def _restrict_private_key_permissions(key_path: str) -> None:
    """Restrict private key file permissions to owner-only on POSIX and restricted NTFS ACLs on Windows."""
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass

    if os.name == "nt":
        try:
            who = subprocess.run(
                ["whoami", "/user", "/fo", "csv", "/nh"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            sid = ""
            if who.returncode == 0 and "," in who.stdout:
                sid = who.stdout.strip().splitlines()[0].split(",")[-1].strip().strip('"')
            grants = [f"*{sid}:(F)"] if sid.startswith("S-1-") else []
            grants.extend(["*S-1-5-18:(F)", "*S-1-5-32-544:(F)"])
            subprocess.run(
                ["icacls", key_path, "/inheritance:r", "/grant:r", *grants],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except Exception:
            pass


def generate_self_signed_cert(
    cert_path: str = "cert.pem",
    key_path: str = "key.pem",
    validity_days: Optional[int] = None,
    key_size: int = 3072,
    extra_sans: Optional[Iterable[str]] = None,
):
    """Generate a fresh RSA private key and self-signed X.509 v3 TLS server certificate."""
    if key_size < 2048:
        raise ValueError("RSA key size must be at least 2048 bits.")

    if validity_days is None:
        validity_days = int(os.getenv("BAITSCOPE_TLS_VALIDITY_DAYS", "365"))
    if validity_days < 1 or validity_days > 825:
        validity_days = max(1, min(validity_days, 825))

    common_name = (os.getenv("BAITSCOPE_TLS_COMMON_NAME") or "localhost").strip() or "localhost"

    # Generate fresh cryptographically secure private key material
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BAITSCOPE Deception Node"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    san_entries = _build_san_entries(extra_sans=extra_sans)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now_utc - datetime.timedelta(minutes=5))
        .not_valid_after(now_utc + datetime.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    key_dir = os.path.dirname(key_path)
    if key_dir:
        os.makedirs(key_dir, exist_ok=True)
    cert_dir = os.path.dirname(cert_path)
    if cert_dir:
        os.makedirs(cert_dir, exist_ok=True)

    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    if os.name != "nt":
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key_bytes)
    else:
        with open(key_path, "wb") as f:
            f.write(key_bytes)
    _restrict_private_key_permissions(key_path)

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


if __name__ == "__main__":
    generate_self_signed_cert()
    print("SSL self-signed certificate (cert.pem) and private key (key.pem) generated successfully!")
