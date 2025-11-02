#!/usr/bin/env python3
"""
Dependencias: pip install cryptography
Ejemplos:
  # Generar par de claves RSA
  python main.py gen-keys --private private.pem --public public.pem --passphrase "miPass"

  # Inicializar archivo vault vacío cifrado con la clave pública
  python main.py init --file vault.bin --public public.pem

  # Agregar un registro al vault (requiere la clave privada para descifrar y la pública para re-encriptar)
  python main.py add --file vault.bin --private private.pem --passphrase "miPass" --public public.pem --name "juan" --password "Secreto123!"

  # Listar registros (requiere la clave privada)
  python main.py list --file vault.bin --private private.pem --passphrase "miPass"
"""
import argparse #para manejar la linea de comandos
import base64 #para convertir binario a texto y viceversa
import json #para guardar registros como JSON
import os #para verificar existencia de archivos
from typing import Dict, Any #dict - diccionario, any - cualquier tipo
import secrets #para generar contraseñas seguras y claves aleatorias
import string #para los caracteres posibles en contraseñas
from getpass import getpass #para pedir contraseñas de forma segura (sin mostrarlas)

#librerias de cryptography para cifrado
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Utilidades de cifrado

def generate_rsa_keypair(private_out: str, public_out: str, passphrase: bytes = None, bits: int = 2048):
    """
    Genera un par de claves RSA:
    - private_out: archivo donde se guarda la clave privada
    - public_out: archivo donde se guarda la clave pública
    - passphrase: cifra la clave privada
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    enc = serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption()
    priv_pem = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
    pub_pem = private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    with open(private_out, "wb") as f: f.write(priv_pem)
    with open(public_out, "wb") as f: f.write(pub_pem)
    print(f"Claves generadas: privada -> {private_out}, pública -> {public_out}")


def load_public_key(pem_path: str):
    #Carga la clave pública desde un archivo PEM
    with open(pem_path, "rb") as f: return serialization.load_pem_public_key(f.read())


def load_private_key(pem_path: str, passphrase: bytes = None):
    #Carga la clave privada desde un archivo PEM, con passphrase si se cifró
    with open(pem_path, "rb") as f: return serialization.load_pem_private_key(f.read(), password=passphrase)


def encrypt_records_to_file(records: Dict[str, str], public_key_path: str, out_file: str):
    public_key = load_public_key(public_key_path)
    plaintext = json.dumps(records, ensure_ascii=False).encode("utf-8")
    #Genera una clave AES-256 aleatoria
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    #Nonce aleatorio de 12 bytes (necesario en AES-GCM para que cada cifrado sea único)
    nonce = secrets.token_bytes(12)
    #Cifra los datos con AES-GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    #Cifra la clave AES con RSA-OAEP (solo se puede descifrar con la clave privada)
    encrypted_key = public_key.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    
    #Guardamos todo en un "contenedor" en JSON
    container = {
        "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8")
    }
    #Guardamos el contenedor en el archivo
    with open(out_file, "w", encoding="utf-8") as f: json.dump(container, f)
    print(f"Archivo cifrado guardado en {out_file}")


def decrypt_records_from_file(file_path: str, private_key_path: str, passphrase: bytes = None) -> Dict[str, str]:
    #Descifra un archivo vault.
    #Primero se descifra la clave AES con RSA-OAEP y luego se usan esos datos para descifrar los registros con AES-GCM.
    with open(file_path, "r", encoding="utf-8") as f: container = json.load(f)
    encrypted_key = base64.b64decode(container["encrypted_key"])
    nonce = base64.b64decode(container["nonce"])
    ciphertext = base64.b64decode(container["ciphertext"])
    private_key = load_private_key(private_key_path, passphrase)

    #Descifra la clave AES
    aes_key = private_key.decrypt(encrypted_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    
    #Descifra los registros con AES-GCM
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return json.loads(plaintext.decode("utf-8"))


# Funcionalidades de vault
def init_empty_vault(out_file: str, public_key_path: str):
    #Crea un vault vacío y lo cifra
    encrypt_records_to_file({}, public_key_path, out_file)


def add_record(file_path: str, private_key_path: str, public_key_path: str, name: str, password: str, passphrase: bytes = None):
    #Agrega un registro al vault
    if not os.path.exists(file_path):
        print("Archivo no existe. Crea uno primero con init.")
        return
    try:
        records = decrypt_records_from_file(file_path, private_key_path, passphrase)
    except Exception as e:
        print("Error al descifrar archivo:", e)
        return
    #Agregamos el nuevo registro
    records[name] = password
    encrypt_records_to_file(records, public_key_path, file_path)
    print(f"Registro agregado: {name}")


def modify_record(file_path: str, private_key_path: str, passphrase: bytes, public_key_path: str, name: str, new_password: str):
    #Modifica la contraseña de un registro existente
    records = decrypt_records_from_file(file_path, private_key_path, passphrase)
    if name not in records: print("No existe el registro:", name); return
    records[name] = new_password
    encrypt_records_to_file(records, public_key_path, file_path)
    print("Registro modificado.")


def delete_record(file_path: str, private_key_path: str, passphrase: bytes, public_key_path: str, name: str):
    #Elimina un registro
    records = decrypt_records_from_file(file_path, private_key_path, passphrase)
    if name not in records: print("No existe el registro:", name); return
    del records[name]
    encrypt_records_to_file(records, public_key_path, file_path)
    print("Registro eliminado.")


def list_records(file_path: str, private_key_path: str, passphrase: bytes):
    #Lista todos los registros del vault
    records = decrypt_records_from_file(file_path, private_key_path, passphrase)
    if not records: print("(vacío)"); return
    for k, v in records.items(): print(f"{k} - {v}")



# Generador y medidor - objetivo secundario
def generate_password(length: int = 12, use_upper=True, use_lower=True, use_digits=True, use_special=True) -> str:
    #Genera una contraseña aleatoria segura
    if length < 4: raise ValueError("Length mínimo 4")
    pools = []
    if use_upper: pools.append(string.ascii_uppercase)
    if use_lower: pools.append(string.ascii_lowercase)
    if use_digits: pools.append(string.digits)
    if use_special: pools.append("!@#$%^&*()-_=+[]{};:,.<>/?")
    #Garantiza al menos un carácter de cada tipo seleccionado
    pwd = [secrets.choice(pool) for pool in pools]
    allchars = "".join(pools)
    while len(pwd) < length: pwd.append(secrets.choice(allchars))
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)


def password_strength(password: str) -> Dict[str, Any]:
    #Evalua fortaleza de una contraseña: largo y diversidad de caracteres
    length = len(password)
    categories = sum([any(c.islower() for c in password), any(c.isupper() for c in password),
                      any(c.isdigit() for c in password), any(not c.isalnum() for c in password)])
    #Puntuacion de 0 a 4
    score = 0
    if length >= 8: score += 1
    if length >= 12: score += 1
    if categories >= 3: score += 1
    if length >= 16 and categories == 4: score += 1
    verdict = {0: "Muy débil", 1: "Débil", 2: "Moderada", 3: "Fuerte", 4: "Muy fuerte"}.get(score, "Indeterminado")
    return {"score": score, "verdict": verdict, "length": length, "categories": categories}


# CLI (gestionar)
def gestionar():
    parser = argparse.ArgumentParser(description="Vault de contraseñas cifrado (RSA + AES-GCM)")
    sub = parser.add_subparsers(dest="cmd")

    # gen-keys
    gk = sub.add_parser("gen-keys", help="Generar par RSA")
    gk.add_argument("--private", required=True)
    gk.add_argument("--public", required=True)
    gk.add_argument("--passphrase", required=False, help="Si se pasa, se usará para cifrar la private PEM")

    # init
    it = sub.add_parser("init", help="Inicializar archivo vault vacío (cifrado con la public key)")
    it.add_argument("--file", required=True)
    it.add_argument("--public", required=True)

    # add
    ad = sub.add_parser("add", help="Agregar registro")
    ad.add_argument("--file", required=True)
    ad.add_argument("--private", required=True)
    ad.add_argument("--public", required=True)
    ad.add_argument("--name", required=True)
    ad.add_argument("--password", required=False)
    ad.add_argument("--passphrase", required=False)

    # list
    ls = sub.add_parser("list", help="Listar registros")
    ls.add_argument("--file", required=True)
    ls.add_argument("--private", required=True)
    ls.add_argument("--passphrase", required=False)

    # modify
    mo = sub.add_parser("modify", help="Modificar registro")
    mo.add_argument("--file", required=True)
    mo.add_argument("--private", required=True)
    mo.add_argument("--public", required=True)
    mo.add_argument("--name", required=True)
    mo.add_argument("--password", required=False)
    mo.add_argument("--passphrase", required=False)

    # delete
    de = sub.add_parser("delete", help="Eliminar registro")
    de.add_argument("--file", required=True)
    de.add_argument("--private", required=True)
    de.add_argument("--public", required=True)
    de.add_argument("--name", required=True)
    de.add_argument("--passphrase", required=False)

    # gen-pass
    gp = sub.add_parser("gen-pass", help="Generar contraseña aleatoria")
    gp.add_argument("--length", type=int, default=12)

    # check-pass
    cp = sub.add_parser("check-pass", help="Medir fortaleza de una contraseña")
    cp.add_argument("--password", required=True)

    args = parser.parse_args()

    if args.cmd == "gen-keys":
        pf = args.passphrase.encode("utf-8") if args.passphrase else None
        generate_rsa_keypair(args.private, args.public, pf)
    elif args.cmd == "init":
        init_empty_vault(args.file, args.public)
    elif args.cmd == "add":
        pw = args.password or getpass("Contraseña para el registro: ")
        pp = args.passphrase.encode("utf-8") if args.passphrase else None
        add_record(args.file, args.private, args.public, args.name, pw, pp)
    elif args.cmd == "list":
        pp = args.passphrase.encode("utf-8") if args.passphrase else None
        list_records(args.file, args.private, pp)
    elif args.cmd == "modify":
        pw = args.password or getpass("Nueva contraseña: ")
        pp = args.passphrase.encode("utf-8") if args.passphrase else None
        modify_record(args.file, args.private, pp, args.public, args.name, pw)
    elif args.cmd == "delete":
        pp = args.passphrase.encode("utf-8") if args.passphrase else None
        delete_record(args.file, args.private, pp, args.public, args.name)
    elif args.cmd == "gen-pass":
        print(generate_password(length=args.length))
    elif args.cmd == "check-pass":
        res = password_strength(args.password)
        print(f"Puntaje: {res['score']} -> {res['verdict']}")
        print(f"Largo: {res['length']}, Categorías: {res['categories']}")
    else:
        parser.print_help()


if __name__ == "__main__":
    gestionar()
