from __future__ import annotations

"""Hashes de archivos (MD5 / SHA-256).

Este módulo hace una sola cosa: calcular el hash de un archivo con OpenSSL.
Es útil para demostrar integridad: si el archivo cambia, el hash cambia.

Nota: MD5 se incluye por práctica/demostración; para integridad real se prefiere SHA-256.
"""

from pathlib import Path
from typing import Literal

from .openssl_wrapper import require_file, require_parent_dir, run_openssl


HashAlgorithm = Literal["md5", "sha256"]


def compute_hash(*, file_path: Path, algorithm: HashAlgorithm, out_file: Path) -> str:
    """Calcula el hash de `file_path` y lo guarda en `out_file`.

    Devuelve el texto que OpenSSL escribió (incluye el nombre del archivo en la salida).
    """
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

    return out_file.read_text(encoding="utf-8", errors="replace").strip()
