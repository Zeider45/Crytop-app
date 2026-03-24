from __future__ import annotations

"""Firmas digitales (SHA-256 + RSA) y verificación.

Idea general, en lenguaje normal:
- Para firmar, primero sacamos el hash SHA-256 del documento (binario).
- Luego firmamos ese hash con la clave privada (RSA).
- Para verificar, extraemos la clave pública desde el certificado del firmante,
  recalculamos el hash del documento y validamos la firma.

Si el documento se altera aunque sea un carácter, la verificación debe fallar.
"""

import tempfile
from pathlib import Path

from .openssl_wrapper import env_with_passphrase, require_file, require_parent_dir, run_openssl


def sign_document(
    *,
    document_path: Path,
    private_key_pem: Path,
    signature_bin: Path,
    passphrase: str | None,
    hash_bin: Path | None = None,
) -> tuple[Path, Path]:
    """Firma `document_path` y produce (firma_bin, hash_bin)."""
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

    Devuelve (ok, mensaje). OpenSSL retorna 0 si verifica, 1 si no.
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
    tampered_out.write_text(
        original + "\n[ALTERADO] Se modificó el contenido.\n",
        encoding="utf-8",
    )

    ok, msg = verify_signature(
        document_path=tampered_out,
        signature_bin=signature_bin,
        certificate_pem=certificate_pem,
    )
    return ok, msg, tampered_out
