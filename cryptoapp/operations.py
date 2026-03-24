from __future__ import annotations

"""Fachada de operaciones criptográficas.

Históricamente este archivo tenía *todas* las funciones juntas.
Para que el proyecto sea más legible (y más fácil de explicar en un informe),
ahora el código está dividido por responsabilidad en módulos pequeños:

- RSA (claves/cifrado/descifrado): `cryptoapp.rsa`
- Hashes: `cryptoapp.hashing`
- Certificados: `cryptoapp.certificates`
- Firma/Verificación: `cryptoapp.signing`

Importante: dejamos este archivo como “entrada única” para no romper el menú
ni los imports existentes. Es decir: `from cryptoapp.operations import rsa_encrypt`
sigue funcionando.
"""

from .certificates import CertArtifacts, generate_self_signed_certificate
from .hashing import HashAlgorithm, compute_hash
from .rsa import generate_rsa_keypair, rsa_decrypt, rsa_encrypt
from .signing import demonstrate_tampering, sign_document, verify_signature

__all__ = [
    "HashAlgorithm",
    "CertArtifacts",
    "rsa_encrypt",
    "rsa_decrypt",
    "generate_rsa_keypair",
    "compute_hash",
    "generate_self_signed_certificate",
    "sign_document",
    "verify_signature",
    "demonstrate_tampering",
]
