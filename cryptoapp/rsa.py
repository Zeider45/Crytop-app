from __future__ import annotations

"""Operaciones RSA (cifrado/descifrado y generación de claves).

Este módulo agrupa lo relacionado con RSA:
- Generar un par de claves (privada + pública).
- Cifrar un mensaje corto con la clave pública.
- Descifrar el resultado con la clave privada (con o sin passphrase).

Por debajo usamos OpenSSL (vía `subprocess`) para evitar reinventar criptografía.
"""

from pathlib import Path

from .openssl_wrapper import env_with_passphrase, require_file, require_parent_dir, run_openssl


def rsa_encrypt(*, message_txt: Path, public_key_pem: Path, out_bin: Path) -> Path:
    """Cifra un archivo de texto usando la clave pública RSA del destinatario."""
    require_file(message_txt, "archivo de mensaje")
    require_file(public_key_pem, "clave pública (.pem)")

    if out_bin.resolve() == message_txt.resolve():
        raise ValueError("El archivo de salida no puede ser el mismo que el archivo de entrada")

    if out_bin.suffix.lower() != ".bin":
        raise ValueError("La salida cifrada debe tener extensión .bin")

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
    """Descifra un .bin generado por `rsa_encrypt` usando la clave privada RSA."""
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


def generate_rsa_keypair(
    *,
    private_key_pem: Path,
    public_key_pem: Path,
    rsa_bits: int = 2048,
    passphrase: str | None = None,
) -> tuple[Path, Path]:
    """Genera un par RSA (privada + pública) con OpenSSL.

    Si `passphrase` viene, la clave privada queda cifrada (AES-256-CBC).
    """
    require_parent_dir(private_key_pem)
    require_parent_dir(public_key_pem)

    extra_env = env_with_passphrase(passphrase) if passphrase else None

    keygen_cmd = [
        "openssl",
        "genpkey",
        "-algorithm",
        "RSA",
        "-pkeyopt",
        f"rsa_keygen_bits:{rsa_bits}",
        "-out",
        str(private_key_pem),
    ]

    if passphrase:
        keygen_cmd += ["-aes-256-cbc", "-pass", "env:OPENSSL_PASS"]

    run_openssl(keygen_cmd, env=extra_env)

    pubout_cmd = [
        "openssl",
        "pkey",
        "-in",
        str(private_key_pem),
        "-pubout",
        "-out",
        str(public_key_pem),
    ]
    if passphrase:
        pubout_cmd += ["-passin", "env:OPENSSL_PASS"]

    run_openssl(pubout_cmd, env=extra_env)

    return private_key_pem, public_key_pem
