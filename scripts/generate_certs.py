"""
TLS / HTTPS Certificate Generator for Privacy-First AIOps Observability Platform.
Task C: Generates local self-signed Root CA and Server TLS certificates for localhost / 127.0.0.1.
Enforces secure TLS 1.3 / HTTPS communication between Edge Collector and SaaS Backend.
"""

from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERTS_DIR = Path(__file__).resolve().parent.parent / "certs"


def generate_tls_certificates(output_dir: Path = CERTS_DIR) -> None:
    """
    Generates:
    1. ca.key & ca.crt (Local Root Certificate Authority)
    2. server.key & server.crt (Server TLS Certificate for localhost/127.0.0.1, signed by CA)
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    ca_key_path = output_dir / "ca.key"
    ca_cert_path = output_dir / "ca.crt"
    server_key_path = output_dir / "server.key"
    server_cert_path = output_dir / "server.crt"

    print(f"Generating TLS certificates in: {output_dir}")

    # 1. Generate Root CA Key & Certificate
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Privacy-First AIOps Security"),
        x509.NameAttribute(NameOID.COMMON_NAME, "AIOps Root CA"),
    ])

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .sign(ca_private_key, hashes.SHA256())
    )

    # 2. Generate Server Key & Certificate (signed by Root CA)
    server_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Privacy-First AIOps SaaS Ingestion"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_subject)
        .public_key(server_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("127.0.0.1"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False
        )
        .sign(ca_private_key, hashes.SHA256())
    )

    # Write Private Keys and Certificates
    ca_key_path.write_bytes(
        ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )
    ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    server_key_path.write_bytes(
        server_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )
    server_cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))

    print(f"Generated Root CA: {ca_cert_path}")
    print(f"Generated Server TLS Certificate: {server_cert_path}")


if __name__ == "__main__":
    generate_tls_certificates()
