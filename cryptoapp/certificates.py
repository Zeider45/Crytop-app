from __future__ import annotations

"""Certificados X.509 autofirmados.

Aquí generamos el "kit" típico para una práctica:
- Clave privada RSA cifrada con passphrase.
- CSR (Certificate Signing Request).
- Certificado X.509 autofirmado (válido por N días).
- Clave pública extraída del certificado.

Se hace con OpenSSL y un archivo temporal para `-extfile` (para el Subject Alternative Name),
porque eso es más portable (funciona bien en Windows/PowerShell y no depende de bash).
"""

import tempfile
from dataclasses import dataclass
from pathlib import Path

from .openssl_wrapper import env_with_passphrase, run_openssl


@dataclass(frozen=True)
class CertArtifacts:
    private_key_pem: Path
    csr_pem: Path
    certificate_pem: Path
    public_key_pem: Path


def generate_self_signed_certificate(
    *,
    output_dir: Path,
    basename: str,
    country: str,
    state: str,
    locality: str,
    organization: str,
    common_name: str,
    subject_alt_dns: str,
    days_valid: int,
    rsa_bits: int,
    passphrase: str,
) -> CertArtifacts:
    """Genera clave privada (encriptada), CSR y certificado autofirmado X.509."""
    output_dir.mkdir(parents=True, exist_ok=True)

    private_key = output_dir / f"{basename}_private_key.pem"
    csr = output_dir / f"{basename}.csr.pem"
    cert = output_dir / f"{basename}_certificate.pem"
    public_key = output_dir / f"{basename}_public_key.pem"

    subj = f"/C={country}/ST={state}/L={locality}/O={organization}/CN={common_name}"

    extra_env = env_with_passphrase(passphrase)

    run_openssl(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-aes-256-cbc",
            "-pkeyopt",
            f"rsa_keygen_bits:{rsa_bits}",
            "-out",
            str(private_key),
            "-pass",
            "env:OPENSSL_PASS",
        ],
        env=extra_env,
    )

    run_openssl(
        [
            "openssl",
            "req",
            "-new",
            "-key",
            str(private_key),
            "-passin",
            "env:OPENSSL_PASS",
            "-out",
            str(csr),
            "-sha256",
            "-subj",
            subj,
        ],
        env=extra_env,
    )

    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as tmp:
        tmp.write(f"subjectAltName=DNS:{subject_alt_dns}\n")
        extfile_path = Path(tmp.name)

    try:
        run_openssl(
            [
                "openssl",
                "x509",
                "-req",
                "-days",
                str(days_valid),
                "-in",
                str(csr),
                "-signkey",
                str(private_key),
                "-passin",
                "env:OPENSSL_PASS",
                "-out",
                str(cert),
                "-extfile",
                str(extfile_path),
            ],
            env=extra_env,
        )
    finally:
        try:
            extfile_path.unlink(missing_ok=True)
        except Exception:
            pass

    run_openssl(
        [
            "openssl",
            "x509",
            "-pubkey",
            "-in",
            str(cert),
            "-out",
            str(public_key),
            "-noout",
        ]
    )

    return CertArtifacts(
        private_key_pem=private_key,
        csr_pem=csr,
        certificate_pem=cert,
        public_key_pem=public_key,
    )
