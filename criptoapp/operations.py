from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .openssl_wrapper import (
    OpenSSLCommandError,
    env_with_passphrase,
    require_file,
    require_parent_dir,
    run_openssl,
)


HashAlgorithm = Literal["md5", "sha256"]


@dataclass(frozen=True)
class CertArtifacts:
    private_key_pem: Path
    csr_pem: Path
    certificate_pem: Path
    public_key_pem: Path


def rsa_encrypt(*, message_txt: Path, public_key_pem: Path, out_bin: Path) -> Path:
    require_file(message_txt, "archivo de mensaje")
    require_file(public_key_pem, "clave pública (.pem)")
    require_parent_dir(out_bin)

    run_openssl(
        [
            "openssl",
            "pkeyutl",
            "-encrypt",
            "-pubin",
            "-inkey",
            str(public_key_pem),
            "-in",
            str(message_txt),
            "-out",
            str(out_bin),
        ]
    )
    return out_bin


def rsa_decrypt(
    *,
    cipher_bin: Path,
    private_key_pem: Path,
    out_txt: Path,
    passphrase: str | None,
) -> Path:
    require_file(cipher_bin, "archivo cifrado (.bin)")
    require_file(private_key_pem, "clave privada (.pem)")
    require_parent_dir(out_txt)

    extra_env = env_with_passphrase(passphrase) if passphrase else None
    args = [
        "openssl",
        "pkeyutl",
        "-decrypt",
        "-inkey",
        str(private_key_pem),
    ]
    if passphrase:
        args += ["-passin", "env:OPENSSL_PASS"]
    args += ["-in", str(cipher_bin), "-out", str(out_txt)]

    run_openssl(args, env=extra_env)
    return out_txt


def compute_hash(*, file_path: Path, algorithm: HashAlgorithm, out_file: Path) -> str:
    require_file(file_path, "archivo a hashear")
    require_parent_dir(out_file)

    run_openssl(
        [
            "openssl",
            "dgst",
            f"-{algorithm}",
            "-out",
            str(out_file),
            str(file_path),
        ]
    )

    digest_text = out_file.read_text(encoding="utf-8", errors="replace").strip()
    return digest_text


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
    """Genera clave privada (encriptada), CSR y certificado autofirmado X.509.

    - Usa un archivo temporal para `-extfile` (evita process-substitution de bash).
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    private_key = output_dir / f"{basename}_private_key.pem"
    csr = output_dir / f"{basename}.csr.pem"
    cert = output_dir / f"{basename}_certificate.pem"
    public_key = output_dir / f"{basename}_public_key.pem"

    subj = (
        f"/C={country}/ST={state}/L={locality}"
        f"/O={organization}/CN={common_name}"
    )

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


def sign_document(
    *,
    document_path: Path,
    private_key_pem: Path,
    signature_bin: Path,
    passphrase: str | None,
    hash_bin: Path | None = None,
) -> tuple[Path, Path]:
    require_file(document_path, "documento a firmar")
    require_file(private_key_pem, "clave privada (.pem)")
    require_parent_dir(signature_bin)

    if hash_bin is None:
        hash_bin = signature_bin.with_suffix(".hash")

    require_parent_dir(hash_bin)

    run_openssl(
        [
            "openssl",
            "dgst",
            "-sha256",
            "-binary",
            "-out",
            str(hash_bin),
            str(document_path),
        ]
    )

    extra_env = env_with_passphrase(passphrase) if passphrase else None

    args = [
        "openssl",
        "pkeyutl",
        "-sign",
        "-inkey",
        str(private_key_pem),
    ]
    if passphrase:
        args += ["-passin", "env:OPENSSL_PASS"]

    args += [
        "-in",
        str(hash_bin),
        "-out",
        str(signature_bin),
        "-pkeyopt",
        "digest:sha256",
    ]

    run_openssl(args, env=extra_env)
    return signature_bin, hash_bin


def verify_signature(
    *,
    document_path: Path,
    signature_bin: Path,
    certificate_pem: Path,
) -> tuple[bool, str]:
    """Verifica firma digital.

    Devuelve (ok, mensaje).

    Nota: `openssl pkeyutl -verify` retorna 0 si verifica, 1 si no.
    """
    require_file(document_path, "documento original")
    require_file(signature_bin, "firma (.bin)")
    require_file(certificate_pem, "certificado (.pem)")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        public_key = tmpdir_path / "public_key.pem"
        document_hash = tmpdir_path / "document.hash"

        run_openssl(
            [
                "openssl",
                "x509",
                "-pubkey",
                "-in",
                str(certificate_pem),
                "-out",
                str(public_key),
                "-noout",
            ]
        )

        run_openssl(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-binary",
                "-out",
                str(document_hash),
                str(document_path),
            ]
        )

        result = run_openssl(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(public_key),
                "-in",
                str(document_hash),
                "-sigfile",
                str(signature_bin),
                "-pkeyopt",
                "digest:sha256",
            ],
            check=False,
        )

        if result.returncode == 0:
            return True, "Firma verificada correctamente (integridad y autenticidad OK)."

        detail = (result.stderr or result.stdout).strip()
        if not detail:
            detail = "La verificación falló (firma inválida o documento alterado)."
        return False, f"Verificación fallida: {detail}"


def demonstrate_tampering(
    *,
    document_path: Path,
    signature_bin: Path,
    certificate_pem: Path,
    tampered_out: Path,
) -> tuple[bool, str, Path]:
    """Crea una copia alterada del documento y verifica que la firma falle."""
    require_file(document_path, "documento original")
    require_parent_dir(tampered_out)

    original = document_path.read_text(encoding="utf-8", errors="replace")
    tampered_out.write_text(original + "\n[ALTERADO] Se modificó el contenido.\n", encoding="utf-8")

    ok, msg = verify_signature(
        document_path=tampered_out,
        signature_bin=signature_bin,
        certificate_pem=certificate_pem,
    )
    return ok, msg, tampered_out
