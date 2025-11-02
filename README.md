# tp-mate-contrasena
1. Objetivo:
Crear una aplicación que permita poder crear, modificar, y eliminar registros del estilo “NOMBRE - CONTRASEÑA”. La misma debe ser capaz de generar un archivo cifrado que almacene las contraseñas y que no pueda ser accedido a menos que se tenga la clave privada.

La aplicación debe leer este archivo, descifrarlo, y poder realizar cambios en las contraseñas almacenadas. Puede utilizarse cualquier algoritmo criptográfico de cifrado, mientras sea seguro.

Objetivo secundario:
A la aplicación, añadirle las siguientes funcionalidades: 
•	Generador de contraseñas aleatorio: permite generar contraseñas aleatorias al momento de crear un nuevo registro en la aplicación.
•	Medidor de fortaleza de contraseñas

2. Dependencias
Para ejecutar este proyecto, se utilizó Python 3 y la librería cryptography:
pip install cryptography

3. Archivos Generados por la Aplicación
Claves RSA:
private.pem: clave privada, necesaria para descifrar el vault y modificar registros. Puede cifrarse con una passphrase.
public.pem: clave pública, necesaria para inicializar y re-encriptar el vault.

Vault de contraseñas:
vault.bin: archivo cifrado que contiene todos los registros NOMBRE - CONTRASEÑA. Solo se puede descifrar usando la clave privada.
Nota: Si se ejecuta nuevamente gen-keys o init con los mismos nombres de archivo, se sobrescribirá los archivos existentes.

4. Uso Paso a Paso - ejecución
4.1 Generar par de claves RSA
python main.py gen-keys --private private.pem --public public.pem --passphrase "miPass"

Genera la clave privada (private.pem) y la pública (public.pem). La passphrase cifra la clave privada, agregando seguridad extra.

4.2 Inicializar un vault vacío
python main.py init --file vault.bin --public public.pem

Crea un archivo vault.bin cifrado con la clave pública.Este archivo comenzará vacío {} y luego podrá contener registros de usuario.

4.3 Agregar un registro
python main.py add --file vault.bin --private private.pem --passphrase "miPass" --public public.pem --name "juan" --password "Secreto123!"


Agrega el registro "juan" - "Secreto123!" al vault. Para modificar el vault, es necesario descifrarlo con la clave privada. Luego se re-encripta usando la clave pública, manteniendo la seguridad. Si no pasas --password, la aplicación pedirá la contraseña de manera interactiva.

4.4 Listar registros
python main.py list --file vault.bin --private private.pem --passphrase "miPass"


Muestra todos los registros almacenados en vault.bin. Solo requiere la clave privada para descifrar el archivo.

4.5 Modificar un registro
python main.py modify --file vault.bin --private private.pem --passphrase "miPass" --public public.pem --name "juan" --password "NuevaPass123!"

Modifica la contraseña de un registro existente.

4.6 Eliminar un registro
python main.py delete --file vault.bin --private private.pem --passphrase "miPass" --public public.pem --name "juan"

Elimina un registro del vault de manera segura.

4.7 Generar contraseña aleatoria
python main.py gen-pass --length 16

Genera una contraseña aleatoria de 16 caracteres. Puede incluir mayúsculas, minúsculas, dígitos y símbolos especiales.

4.8 Medir fortaleza de una contraseña
python main.py check-pass --password "Hola123!"


Evalúa la seguridad de una contraseña y devuelve:
Score: de 0 a 4
Veredicto: Muy débil / Débil / Moderada / Fuerte / Muy fuerte
Largo y categorías (mayúsculas, minúsculas, dígitos, símbolos)

5. Justificación del Código

Cifrado híbrido:
AES-GCM cifra los registros de forma rápida y segura.
RSA-OAEP cifra la clave AES, garantizando que solo quien tenga la clave privada pueda descifrar el vault.


Seguridad:
La clave privada puede cifrarse con passphrase.
Se usa AES-256-GCM con nonce aleatorio para cada cifrado. Los datos nunca se almacenan en texto plano.

6. Glosario de términos

Vault: Es un archivo seguro donde se almacenan todos los registros de usuario (NOMBRE - CONTRASEÑA). Está cifrado para que nadie pueda leerlo sin la clave correcta.

Clave pública (public key): Se utiliza para cifrar información. Puede compartirse sin riesgo, ya que la información cifrada con esta clave solo puede descifrarse con la clave privada correspondiente.

Clave privada (private key): Se utiliza para descifrar la información cifrada con la clave pública. Debe mantenerse en secreto, porque quien tenga esta clave puede acceder a todos los datos del vault.

AES-GCM: Algoritmo de cifrado simétrico, rápido y seguro. Se usa para cifrar directamente los datos (registros de usuario) dentro del vault.

RSA-OAEP: Algoritmo de cifrado asimétrico. Se usa para cifrar la clave AES, de modo que solo quien tenga la clave privada pueda obtenerla y descifrar los registros.

Passphrase: Contraseña que puede proteger la clave privada, agregando una capa extra de seguridad.

Nonce: Número aleatorio usado en AES-GCM para asegurar que cada cifrado sea único, incluso si se cifran los mismos datos más de una vez.

Generador de contraseñas: Función que crea contraseñas aleatorias seguras, combinando mayúsculas, minúsculas, números y símbolos.

Medidor de fortaleza: Evalúa qué tan segura es una contraseña según su longitud y la variedad de caracteres que contiene.

Archivo PEM: Formato de archivo que almacena claves criptográficas en texto Base64 con encabezados y pies específicos como (-----BEGIN PUBLIC KEY-----). Tanto claves públicas como privadas pueden estar en PEM.
