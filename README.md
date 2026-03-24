# CryptoApp (OpenSSL + Python)

Micro proyecto práctico: Interfaz en Python para Gestión de Criptografía y Firmas Digitales usando **OpenSSL** vía `subprocess`.

## Requisitos

- Linux (Ubuntu 22.04 recomendado) con `openssl` instalado.
- Python 3.8+

> Si estás en Windows, lo más simple es usar **WSL2 (Ubuntu)** y ejecutar allí el proyecto.

## Ejecutar

Desde la raíz del proyecto:

```bash
python -m cryptoapp
```

## Estructura

- `cryptoapp/openssl_wrapper.py`: wrapper seguro para invocar OpenSSL.
- `cryptoapp/operations.py`: fachada (re-export) para no romper imports existentes.
- `cryptoapp/rsa.py`: RSA (claves/cifrado/descifrado).
- `cryptoapp/hashing.py`: hashes (MD5/SHA256).
- `cryptoapp/certificates.py`: certificado X.509 autofirmado.
- `cryptoapp/signing.py`: firma/verificación + demostración de alteración.
- `cryptoapp/menu.py`: menú interactivo.
- `docs/EXPLICACION_PASO_A_PASO.md`: explicación detallada para el informe.
- `examples/`: archivos de texto de ejemplo.
- `output/`: salidas generadas (cifrados, hashes, firmas, certificados).

## Nota importante (RSA)

RSA no sirve para cifrar mensajes grandes directamente (tiene límite por tamaño/relación con el padding). Esta app está pensada para **mensajes cortos** o archivos pequeños de texto, tal como la práctica de terminal.
