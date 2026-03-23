from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


@dataclass(frozen=True)
class OpenSSLResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str


class OpenSSLCommandError(RuntimeError):
    def __init__(self, result: OpenSSLResult):
        msg = (
            "Error ejecutando OpenSSL\n"
            f"Comando: {' '.join(result.args)}\n"
            f"Código: {result.returncode}\n"
            f"STDOUT: {result.stdout.strip()}\n"
            f"STDERR: {result.stderr.strip()}"
        )
        super().__init__(msg)
        self.result = result


def ensure_openssl_available() -> None:
    """Verifica que `openssl` esté disponible en PATH."""
    run_openssl(["openssl", "version"], check=True)


def _merge_env(extra_env: Mapping[str, str] | None) -> dict[str, str]:
    env = dict(os.environ)
    if extra_env:
        for k, v in extra_env.items():
            env[str(k)] = str(v)
    return env


def run_openssl(
    args: Sequence[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    input_bytes: bytes | None = None,
    check: bool = True,
) -> OpenSSLResult:
    """Ejecuta un comando OpenSSL y devuelve stdout/stderr.

    - No usa shell.
    - Si `check=True` y el código de retorno != 0, lanza OpenSSLCommandError.
    """
    completed = subprocess.run(
        list(args),
        cwd=str(cwd) if cwd else None,
        env=_merge_env(env),
        input=input_bytes,
        capture_output=True,
        text=False,
    )

    result = OpenSSLResult(
        args=list(args),
        returncode=completed.returncode,
        stdout=(completed.stdout or b"").decode("utf-8", errors="replace"),
        stderr=(completed.stderr or b"").decode("utf-8", errors="replace"),
    )

    if check and result.returncode != 0:
        raise OpenSSLCommandError(result)

    return result


def env_with_passphrase(passphrase: str, var_name: str = "OPENSSL_PASS") -> dict[str, str]:
    """Construye un env que expone la passphrase solo a ese subprocess.

    Nota: evita pasar la contraseña en la línea de comandos. Sigue existiendo en memoria
    del proceso Python por un instante (inevitable si el usuario la teclea).
    """
    return {var_name: passphrase}


def require_file(path: Path, description: str) -> None:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"No se encontró {description}: {path}")


def require_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
