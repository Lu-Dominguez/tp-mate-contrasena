# tp-mate-contrasena: Vault de Contraseñas Cifrado (RSA + AES-GCM)

## Objetivo del Proyecto

Crear una aplicación de línea de comandos robusta que funcione como un **vault de contraseñas** seguro. La aplicación permite crear, modificar y eliminar registros del estilo **"NOMBRE - CONTRASEÑA"**, almacenándolos en un archivo cifrado que solo puede ser accedido por el propietario de la **clave privada**.

### Objetivos Secundarios

  * **Generador de Contraseñas:** Incluir una herramienta para generar contraseñas aleatorias y seguras.
  * **Medidor de Fortaleza:** Implementar una función para evaluar la seguridad de cualquier contraseña.

-----

## Tecnologías y Dependencias

Este proyecto está construido en **Python 3** y requiere la poderosa librería `cryptography` para todas las operaciones criptográficas.

```bash
# Instalación de dependencias
pip install cryptography
```

-----

## Arquitectura de Cifrado Híbrido

El sistema utiliza un enfoque de **cifrado híbrido** para combinar la seguridad asimétrica de RSA con la velocidad del cifrado simétrico AES-GCM.

  * **AES-GCM (Simétrico):** Se utiliza para cifrar y descifrar rápidamente los **registros de contraseñas (el vault)**.
  * **RSA-OAEP (Asimétrico):** Se utiliza para cifrar la **clave AES** aleatoria. Esto garantiza que solo la **clave privada** pueda descifrar la clave AES y, por ende, acceder al contenido del vault.

| Componente | Algoritmo | Función |
| :--- | :--- | :--- |
| **Registros del Vault** | AES-256-GCM | Cifrado/Descifrado rápido de los datos. |
| **Clave AES** | RSA-OAEP | Cifrado asimétrico para la clave de sesión. |
| **Clave Privada** | Serialización con Passphrase | Protección adicional de la clave privada. |

-----

## Archivos Generados por la Aplicación

| Archivo | Contenido | Función |
| :--- | :--- | :--- |
| `private.pem` | **Clave Privada** | Necesaria para **descifrar** el vault y modificar registros. Puede cifrarse con una *passphrase*. |
| `public.pem` | **Clave Pública** | Necesaria para **inicializar** el vault y **re-encriptar** los datos después de una modificación. |
| `vault.bin` | **Vault Cifrado** | Contiene todos los registros `NOMBRE - CONTRASEÑA`. Solo se puede leer con la clave privada. |

> **Nota:** Ejecutar nuevamente `gen-keys` o `init` con los mismos nombres de archivo sobrescribirá los archivos existentes.

-----

## Guía de Uso Paso a Paso

El script principal se llama `main.py` y se ejecuta a través de comandos en la terminal.

### 1\. Generar Par de Claves RSA

Este es el primer paso y establece tus credenciales de cifrado. La `passphrase` es opcional, pero recomendada.

```bash
python main.py gen-keys --private private.pem --public public.pem --passphrase "miPass"
# La passphrase cifra la clave privada (private.pem), añadiendo una capa de seguridad.
```

### 2\. Inicializar un Vault Vacío

Crea el archivo binario del vault, cifrado con tu clave pública.

```bash
python main.py init --file vault.bin --public public.pem
# Crea vault.bin, un archivo cifrado vacío ({}) listo para guardar registros.
```

### 3\. Gestionar Registros

Para cualquier operación que **modifique** el vault (`add`, `modify`, `delete`), se necesita la **clave privada** para descifrar el contenido, y la **clave pública** para volver a cifrarlo de forma segura.

#### Agregar un Registro (`add`)

```bash
python main.py add --file vault.bin --private private.pem --passphrase "miPass" --public public.pem --name "juan" --password "Secreto123!"
# Opción: Si omites --password, se te pedirá interactivamente de forma segura (sin eco).
```

#### Listar Registros (`list`)

Solo requiere la clave privada para descifrar y mostrar el contenido.

```bash
python main.py list --file vault.bin --private private.pem --passphrase "miPass"
```

#### Modificar un Registro (`modify`)

```bash
python main.py modify --file vault.bin --private private.pem --passphrase "miPass" --public public.pem --name "juan" --password "NuevaPass123!"
# Opción: Si omites --password, se te pedirá interactivamente.
```

#### Eliminar un Registro (`delete`)

```bash
python main.py delete --file vault.bin --private private.pem --passphrase "miPass" --public public.pem --name "juan"
```

### 4\. Herramientas de Contraseñas

#### Generar Contraseña Aleatoria (`gen-pass`)

Crea una contraseña segura con una combinación de mayúsculas, minúsculas, dígitos y símbolos.

```bash
python main.py gen-pass --length 16
# Genera una contraseña de 16 caracteres.
```

#### Medir Fortaleza (`check-pass`)

Evalúa la seguridad de una contraseña basándose en su longitud y la diversidad de caracteres (categorías).

```bash
python main.py check-pass --password "Hola123!"

# Output de ejemplo:
# Puntaje: 2 -> Moderada
# Largo: 8, Categorías: 4
```

**Escala de Puntuación:**

  * **0:** Muy débil
  * **1:** Débil
  * **2:** Moderada
  * **3:** Fuerte
  * **4:** Muy fuerte

-----

## Glosario de Términos Criptográficos

| Término | Concepto |
| :--- | :--- |
| **Vault** | Archivo seguro (`vault.bin`) que almacena los registros cifrados. |
| **Clave Pública** | Se usa para **cifrar** los datos. Puede ser compartida. |
| **Clave Privada** | Se usa para **descifrar** los datos. Debe ser secreta. |
| **AES-GCM** | Algoritmo de cifrado simétrico, rápido y seguro, usado para los datos del vault. |
| **RSA-OAEP** | Algoritmo de cifrado asimétrico, usado para proteger la clave AES. |
| **Passphrase** | Contraseña de protección adicional para la clave privada. |
| **Nonce** | Valor único y aleatorio usado en AES-GCM para asegurar que cada cifrado sea diferente. |