from __future__ import annotations

import sys
from datetime import datetime
from getpass import getpass
from pathlib import Path

from .openssl_wrapper import OpenSSLCommandError, ensure_openssl_available
from .operations import (
    compute_hash,
    demonstrate_tampering,
    generate_self_signed_certificate,
    generate_rsa_keypair,
    rsa_decrypt,
    rsa_encrypt,
    sign_document,
    verify_signature,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "output"


def _now_tag() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _input_path(prompt: str) -> Path:
    return Path(input(prompt).strip().strip('"').strip("'"))


def _require_existing_file(path: Path, label: str) -> None:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"No existe {label}: {path}")


def _output_path(default_name: str) -> Path:
    raw = input(
        f"Ruta de salida (Enter para usar output/{default_name}): "
    ).strip().strip('"').strip("'")
    if raw:
        return Path(raw)
    DEFAULT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    return DEFAULT_OUTPUT_DIR / default_name


def _ask_passphrase(optional: bool = False) -> str | None:
    if optional:
        use = input("¿La clave privada tiene contraseña? [s/N]: ").strip().lower()
        if use not in {"s", "si", "sí", "y", "yes"}:
            return None
    return getpass("Contraseña de la clave privada (no se muestra): ")


def _read_text_to_tempfile(text: str) -> Path:
    DEFAULT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    tmp = DEFAULT_OUTPUT_DIR / f"mensaje_{_now_tag()}.txt"
    tmp.write_text(text, encoding="utf-8")
    return tmp


def menu_loop() -> None:
    while True:
        print(
            "\n============== CryptoApp ===============\n"
            "1) Generar claves RSA (privada + pública)\n"
            "2) Cifrar mensaje con RSA\n"
            "3) Descifrar mensaje con RSA\n"
            "4) Generar hash (MD5 o SHA256)\n"
            "5) Generar certificado digital X.509 autofirmado\n"
            "6) Firmar digitalmente un documento\n"
            "7) Verificar firma digital\n"
            "8) Demostración de alteración \n"
            "0) Salir\n"
        )
        option = input("Selecciona una opción: ").strip()

        try:
            if option == "1":
                option_generate_rsa_keypair()
            elif option == "2":
                option_rsa_encrypt()
            elif option == "3":
                option_rsa_decrypt()
            elif option == "4":
                option_hash()
            elif option == "5":
                option_certificate()
            elif option == "6":
                option_sign()
            elif option == "7":
                option_verify()
            elif option == "8":
                option_tamper_demo()
            elif option == "0":
                print("Saliendo...")
                return
            else:
                print("Opción inválida.")
        except (FileNotFoundError, ValueError) as e:
            print(f"[ERROR] {e}")
        except OpenSSLCommandError as e:
            print(f"[OPENSSL ERROR]\n{e}")
        except KeyboardInterrupt:
            print("\nInterrumpido por el usuario.")
            return


def option_rsa_encrypt() -> None:
    print("\n--- RSA: Cifrar ---")
    mode = input("¿Quieres introducir (1) texto o (2) ruta a .txt? [1/2]: ").strip()

    if mode == "2":
        message_txt = _input_path("Ruta del archivo .txt: ")
        _require_existing_file(message_txt, "archivo de mensaje")
    else:
        text = input("Escribe el mensaje (corto): ")
        message_txt = _read_text_to_tempfile(text)

    public_key = _input_path("Ruta de la clave pública del destinatario (.pem): ")
    _require_existing_file(public_key, "clave pública")

    out_bin = _output_path(f"mensaje_cifrado_{_now_tag()}.bin")

    if out_bin.suffix.lower() != ".bin":
        raise ValueError("La salida cifrada debe terminar en .bin, el archivo de salida actual es: {out_bin}")

    rsa_encrypt(message_txt=message_txt, public_key_pem=public_key, out_bin=out_bin)
    print(f"OK. Archivo cifrado generado en: {out_bin}")


def option_rsa_decrypt() -> None:
    print("\n--- RSA: Descifrar ---")
    cipher_bin = _input_path("Ruta del archivo cifrado (.bin): ")
    _require_existing_file(cipher_bin, "archivo cifrado")

    private_key = _input_path("Ruta de tu clave privada (.pem): ")
    _require_existing_file(private_key, "clave privada")

    passphrase = _ask_passphrase(optional=True)

    out_txt = _output_path(f"mensaje_descifrado_{_now_tag()}.txt")
    rsa_decrypt(
        cipher_bin=cipher_bin,
        private_key_pem=private_key,
        out_txt=out_txt,
        passphrase=passphrase,
    )

    print(f"OK. Mensaje descifrado guardado en: {out_txt}")
    try:
        print("\nContenido:\n" + out_txt.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        print("(No se pudo mostrar el contenido; revisa el archivo de salida.)")


def option_hash() -> None:
    print("\n--- Hash (MD5/SHA256) ---")
    file_path = _input_path("Ruta del archivo de texto: ")
    _require_existing_file(file_path, "archivo")

    alg = input("Algoritmo [md5/sha256]: ").strip().lower()
    if alg not in {"md5", "sha256"}:
        raise ValueError("Algoritmo inválido. Usa md5 o sha256.")

    suffix = "md5" if alg == "md5" else "sha256"
    out_file = _output_path(f"hash_{_now_tag()}.{suffix}")

    digest = compute_hash(file_path=file_path, algorithm=alg, out_file=out_file)
    print(f"OK. Hash guardado en: {out_file}")
    print(f"Hash: {digest}")


def option_certificate() -> None:
    print("\n--- Certificado X.509 autofirmado ---")
    output_dir_raw = input("Directorio de salida (Enter para usar output/): ").strip()
    output_dir = Path(output_dir_raw) if output_dir_raw else DEFAULT_OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    basename = input("Nombre base para archivos (ej: ucv_carlos): ").strip() or f"cert_{_now_tag()}"

    country = input("P (País, 2 letras; ej: VE): ").strip() or "VE"
    state = input("E (Estado): ").strip() or "Distrito Capital"
    locality = input("C (Ciudad): ").strip() or "Caracas"
    organization = input("O (Organización): ").strip() or "UCV"
    common_name = input("N (Nombre): ").strip() or "Estudiante"
    san = input("DNS (ej: ejemplo.com): ").strip() or "ejemplo.com"

    days_valid_raw = input("Días de validez (Enter=365): ").strip()
    days_valid = int(days_valid_raw) if days_valid_raw else 365

    bits_raw = input("Bits RSA (Enter=2048): ").strip()
    rsa_bits = int(bits_raw) if bits_raw else 2048

    passphrase = getpass("Contraseña para proteger la clave privada (no se muestra): ")

    artifacts = generate_self_signed_certificate(
        output_dir=output_dir,
        basename=basename,
        country=country,
        state=state,
        locality=locality,
        organization=organization,
        common_name=common_name,
        subject_alt_dns=san,
        days_valid=days_valid,
        rsa_bits=rsa_bits,
        passphrase=passphrase,
    )

    print("OK. Archivos generados:")
    print(f"- Clave privada: {artifacts.private_key_pem}")
    print(f"- CSR: {artifacts.csr_pem}")
    print(f"- Certificado: {artifacts.certificate_pem}")
    print(f"- Clave pública (extraída del certificado): {artifacts.public_key_pem}")


def option_sign() -> None:
    print("\n--- Firma digital ---")
    document = _input_path("Ruta del documento a firmar: ")
    _require_existing_file(document, "documento")

    private_key = _input_path("Ruta de la clave privada (.pem): ")
    _require_existing_file(private_key, "clave privada")

    passphrase = _ask_passphrase(optional=True)

    signature_out = _output_path(f"firma_{_now_tag()}.bin")

    signature_bin, hash_bin = sign_document(
        document_path=document,
        private_key_pem=private_key,
        signature_bin=signature_out,
        passphrase=passphrase,
    )

    print("OK. Firma generada:")
    print(f"- Firma (.bin): {signature_bin}")
    print(f"- Hash binario (.hash): {hash_bin}")


def option_verify() -> None:
    print("\n--- Verificar firma ---")
    document = _input_path("Ruta del documento original: ")
    _require_existing_file(document, "documento")

    signature = _input_path("Ruta de la firma (.bin): ")
    _require_existing_file(signature, "firma")

    certificate = _input_path("Ruta del certificado del firmante (.pem): ")
    _require_existing_file(certificate, "certificado")

    ok, msg = verify_signature(
        document_path=document,
        signature_bin=signature,
        certificate_pem=certificate,
    )
    print("OK" if ok else "FALLÓ")
    print(msg)


def option_tamper_demo() -> None:
    print("\n--- Demostración de alteración (integridad) ---")
    document = _input_path("Ruta del documento original: ")
    _require_existing_file(document, "documento")

    signature = _input_path("Ruta de la firma (.bin): ")
    _require_existing_file(signature, "firma")

    certificate = _input_path("Ruta del certificado (.pem): ")
    _require_existing_file(certificate, "certificado")

    tampered_out = _output_path(f"documento_alterado_{_now_tag()}.txt")

    ok, msg, out_path = demonstrate_tampering(
        document_path=document,
        signature_bin=signature,
        certificate_pem=certificate,
        tampered_out=tampered_out,
    )

    print(f"Copia alterada creada en: {out_path}")
    print("(Se espera que falle) Resultado:")
    print("OK" if ok else "FALLÓ")
    print(msg)


def option_generate_rsa_keypair() -> None:
    print("\n--- RSA: Generar par de claves ---")
    private_key_path = _output_path(f"rsa_private_{_now_tag()}.pem")
    public_key_path = _output_path(f"rsa_public_{_now_tag()}.pem")

    bits_raw = input("Bits RSA (Enter=2048): ").strip()
    rsa_bits = int(bits_raw) if bits_raw else 2048

    passphrase = _ask_passphrase(optional=True)

    private_key, public_key = generate_rsa_keypair(
        private_key_pem=private_key_path,
        public_key_pem=public_key_path,
        rsa_bits=rsa_bits,
        passphrase=passphrase,
    )

    print("OK. Par de claves generado:")
    print(f"- Clave privada: {private_key}")
    print(f"- Clave pública: {public_key}")


def main() -> None:
    try:
        ensure_openssl_available()
    except Exception as e:
        print("[ERROR] No se pudo ejecutar `openssl`.\n"
              "Ejecuta este proyecto en Linux con OpenSSL instalado (WSL2 también sirve).\n"
              f"Detalle: {e}")
        sys.exit(1)

    DEFAULT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    menu_loop()
