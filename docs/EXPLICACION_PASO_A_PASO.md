# Explicación paso a paso — CryptoApp (Python + OpenSSL)

Este documento explica **cómo está programada** la aplicación y cómo cada opción del menú ejecuta comandos **reales** de OpenSSL usando `subprocess` (sin librerías criptográficas externas).

## 1) Idea general

La app es una interfaz por consola que guía al usuario con un menú. Cada operación criptográfica se implementa como una función de alto nivel que:

1. Valida rutas de archivos.
2. Construye el comando de OpenSSL (lista de argumentos, sin `shell=True`).
3. Ejecuta el comando con `subprocess.run(capture_output=True, ...)`.
4. Interpreta la salida/código de retorno y muestra un mensaje claro.

## 2) Estructura del proyecto

- `CryptoApp/openssl_wrapper.py`
  - Capa “wrapper” que centraliza **cómo se llama OpenSSL**.
  - Define:
    - `run_openssl(args, ...)`: ejecuta el comando y captura stdout/stderr.
    - `OpenSSLCommandError`: excepción con detalles del comando fallido.
    - `ensure_openssl_available()`: prueba `openssl version`.
    - `env_with_passphrase()`: pasa contraseñas por **variable de entorno** (más seguro que línea de comandos).

- `CryptoApp/operations.py`
  - Implementa las operaciones del proyecto como funciones.
  - Cada función corresponde a 1 módulo del enunciado.

- `CryptoApp/menu.py`
  - Presenta el menú interactivo.
  - Pide datos con `input()` / `getpass()`.
  - Llama a las funciones en `operations.py`.

- `examples/`
  - Textos de prueba (`mensaje.txt`, `documento.txt`) para capturas.

- `output/`
  - Carpeta por defecto donde se guardan: hashes, firmas, mensajes cifrados/descifrados, certificados.

## 3) Cómo se invoca OpenSSL (detalle técnico)

La pieza clave es la función `run_openssl()`:

- Usa `subprocess.run([...], capture_output=True)` con argumentos como lista.
- **No usa `shell=True`** para evitar problemas de seguridad e interpretación de caracteres.
- Si el comando falla (código != 0), lanza `OpenSSLCommandError` con:
  - Comando ejecutado.
  - Código de retorno.
  - STDOUT / STDERR.

Esto permite que el menú muestre errores amigables y que el informe pueda explicar qué salió mal cuando ocurra un fallo.

## 4) Manejo de contraseñas (claves privadas)

Cuando una clave privada está cifrada con contraseña, OpenSSL requiere esa contraseña para operar.

En vez de pasarla como `-passin pass:...` (queda visible en historial y lista de procesos), la app:

- Pide la contraseña con `getpass()`.
- La exporta **solo para ese subprocess** como `OPENSSL_PASS`.
- Usa `-passin env:OPENSSL_PASS` (o `-pass env:OPENSSL_PASS` al generar la clave).

Nota: la contraseña vive brevemente en memoria del proceso Python (inevitable porque el usuario la teclea), pero no queda en el comando.

## 5) Módulo 1 — Cifrar mensaje con RSA

**Flujo:**

1. El usuario introduce:
   - Texto (se guarda temporalmente como `.txt` en `output/`) o una ruta `.txt`.
   - Ruta a la clave pública del destinatario (archivo `.pem`).
2. Se ejecuta:

```bash
openssl pkeyutl -encrypt -pubin -inkey clave_publica.pem -in mensaje.txt -out mensaje_cifrado.bin
```

**Implementación:** función `rsa_encrypt()`.

**Nota importante (limitación de RSA):** RSA no es para archivos grandes; funciona para mensajes pequeños. Para proyectos reales se usa cifrado híbrido, pero aquí se sigue el alcance del enunciado.

## 6) Módulo 1 — Descifrar mensaje con RSA

**Flujo:**

1. El usuario introduce:
   - Ruta del archivo cifrado `.bin`.
   - Ruta a su clave privada `.pem`.
   - (Opcional) contraseña si la clave está protegida.
2. Se ejecuta:

```bash
openssl pkeyutl -decrypt -inkey clave_privada.pem -in mensaje_cifrado.bin -out mensaje_descifrado.txt
```

**Implementación:** función `rsa_decrypt()`.

El menú intenta imprimir el contenido del `.txt` descifrado para que sea visible en capturas.

## 7) Módulo 2 — Hash (MD5 o SHA256)

**Flujo:**

1. El usuario selecciona un archivo.
2. Selecciona `md5` o `sha256`.
3. Se ejecuta (según algoritmo):

```bash
openssl dgst -md5 -out hash.md5 archivo.txt
# o
openssl dgst -sha256 -out hash.sha256 archivo.txt
```

**Implementación:** función `compute_hash()`.

El hash se guarda en el archivo de salida y además se muestra por pantalla.

## 8) Módulo 3 — Certificado digital X.509 autofirmado

**Objetivo:** simular el flujo PKI básico: generar clave privada, CSR, y certificado autofirmado.

### 8.1 Datos solicitados

El usuario introduce campos típicos del sujeto X.509:

- `C, ST, L, O, CN`
- `subjectAltName` tipo DNS (p.ej. `ejemplo.com`)

### 8.2 Comandos ejecutados

1. Generar clave privada RSA cifrada con AES-256:

```bash
openssl genpkey -algorithm RSA -aes-256-cbc -pkeyopt rsa_keygen_bits:2048 -out private_key.pem
```

2. Generar CSR:

```bash
openssl req -new -key private_key.pem -out csr.pem -sha256 -subj "/C=.../ST=.../L=.../O=.../CN=..."
```

3. Generar certificado autofirmado:

```bash
openssl x509 -req -days 365 -in csr.pem -signkey private_key.pem -out certificate.pem -extfile ext.cnf
```

**Detalle importante:** en la práctica se usa `-extfile <(printf "subjectAltName=DNS:...")` (process substitution de bash). En Python, para evitar depender de bash, se crea un archivo temporal `ext.cnf` y se pasa su ruta.

**Implementación:** función `generate_self_signed_certificate()`.

Además, para facilitar pruebas de RSA, se extrae la **clave pública** desde el certificado y se guarda como `*_public_key.pem` usando:

```bash
openssl x509 -pubkey -in certificate.pem -out public_key.pem -noout
```

## 9) Módulo 4 — Firmar digitalmente un documento

**Concepto:** una firma digital típicamente firma un resumen (hash) del documento.

**Comandos ejecutados:**

1. Calcular hash binario SHA256:

```bash
openssl dgst -sha256 -binary -out documento.hash documento.txt
```

2. Firmar el hash con la clave privada:

```bash
openssl pkeyutl -sign -inkey private_key.pem -in documento.hash -out firma.bin -pkeyopt digest:sha256
```

**Implementación:** función `sign_document()`.

Salida:

- `firma.bin` (firma)
- `firma.hash` (hash binario usado para firmar)

## 10) Módulo 5 — Verificar firma digital

**Idea:**

1. Extraer la clave pública desde el certificado.
2. Calcular el hash del documento recibido.
3. Verificar la firma con la clave pública.

**Comandos ejecutados:**

1. Extraer clave pública:

```bash
openssl x509 -pubkey -in certificate.pem -out public_key.pem -noout
```

2. Hash binario del documento:

```bash
openssl dgst -sha256 -binary -out documento_recibido.hash documento.txt
```

3. Verificar:

```bash
openssl pkeyutl -verify -pubin -inkey public_key.pem -in documento_recibido.hash -sigfile firma.bin -pkeyopt digest:sha256
```

**Interpretación:**

- Si el comando retorna `0`: firma válida.
- Si retorna `1`: firma inválida (posible alteración o firma/certificado incorrectos).

**Implementación:** función `verify_signature()`.

## 11) Módulo 6 — Demostración de alteración (recomendado)

Este módulo crea una **copia alterada** del documento (agrega una línea) y vuelve a verificar la firma.

**Resultado esperado:** la verificación debe fallar, demostrando la propiedad de **integridad**. Esto apoya el análisis del informe sobre:

- Qué pasa si se modifica el mensaje después de firmado.
- Relación con autenticidad y (según el contexto) no repudio.

**Implementación:** función `demonstrate_tampering()`.

## 12) Capturas para el informe (sugerencia)

Para cubrir la rúbrica, toma capturas de:

- Generación de certificado (rutas de `private_key`, `csr`, `certificate`).
- Firma de `examples/documento.txt`.
- Verificación exitosa.
- Demostración de alteración con verificación fallida.
- Hash MD5 y SHA256 de `examples/mensaje.txt`.

## 13) Cómo ejecutar (Linux)

Desde la raíz del proyecto:

```bash
python3 -m CryptoApp
```

Si estás en Windows:

- Usar WSL2 (Ubuntu), instalar `python3` y ejecutar lo anterior.

## 14) Manejo de errores

El menú captura:

- `FileNotFoundError`: rutas inválidas.
- `OpenSSLCommandError`: error devuelto por OpenSSL (comando + stderr).
- `KeyboardInterrupt`: salida limpia.

Esto asegura que el usuario no vea trazas largas, sino mensajes claros.
