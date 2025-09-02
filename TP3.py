# -*- coding: utf-8 -*-
"""
TP 3 – Cryptographie avancée et gestion des clés
Auteur : Lucas FOURRAGE - Théo GODIER - Marvin CHARMILLON
Description : Génère des clés RSA, chiffre/déchiffre avec RSA/AES, signe/vérifie et sécurise un mot de passe.
Nécessite : pycryptodome, bcrypt (pip install pycryptodome bcrypt)
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import bcrypt
import os

# Génération d'une paire de clés RSA et sauvegarde sur disque
def generer_cles():
    cle = RSA.generate(2048)
    with open("private.pem", "wb") as f:
        f.write(cle.export_key())
    with open("public.pem", "wb") as f:
        f.write(cle.publickey().export_key())
    print("[OK] Clés RSA générées et enregistrées.")

# Chiffrement RSA
def chiffrer_rsa(message, public_key_path="public.pem"):
    with open(public_key_path, "rb") as f:
        key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(key)
    chiffré = cipher_rsa.encrypt(message.encode())
    return chiffré

# Déchiffrement RSA
def dechiffrer_rsa(ciphertext, private_key_path="private.pem"):
    with open(private_key_path, "rb") as f:
        key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(key)
    déchiffré = cipher_rsa.decrypt(ciphertext)
    return déchiffré.decode()

# Chiffrement AES (mode GCM pour intégrité)
def chiffrer_aes(message):
    key = get_random_bytes(32)  # AES-256
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return key, cipher.nonce, ciphertext, tag

# Déchiffrement AES
def dechiffrer_aes(key, nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()

# Signature RSA
def signer_message(message, private_key_path="private.pem"):
    with open(private_key_path, "rb") as f:
        key = RSA.import_key(f.read())
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(key).sign(h)
    return signature

# Vérification signature RSA
def verifier_signature(message, signature, public_key_path="public.pem"):
    with open(public_key_path, "rb") as f:
        key = RSA.import_key(f.read())
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# Sécurisation mot de passe avec bcrypt
def securiser_mdp(motdepasse):
    hash = bcrypt.hashpw(motdepasse.encode(), bcrypt.gensalt())
    return hash

def verifier_mdp(motdepasse, le_hash):
    return bcrypt.checkpw(motdepasse.encode(), le_hash)

# EXEMPLES D’UTILISATION

if __name__ == "__main__":
    # 1. Génération clés
    generer_cles()
    message = "Confidentiel : Le centre est déplacé à 16h."
    
    # 2. Chiffrement/Déchiffrement RSA
    chiffré_rsa = chiffrer_rsa(message)
    print("RSA → Chiffré:", chiffré_rsa)
    print("RSA → Déchiffré:", dechiffrer_rsa(chiffré_rsa))
    
    # 3. Chiffrement/Déchiffrement AES
    key, nonce, ciphertext, tag = chiffrer_aes(message)
    print("AES → Chiffré:", ciphertext)
    print("AES → Déchiffré:", dechiffrer_aes(key, nonce, ciphertext, tag))
    
    # 4. Signature
    signature = signer_message(message)
    print("Signature générée:", signature.hex())
    ok = verifier_signature(message, signature)
    print("Signature valide ? ", ok)
    
    # Sécurisation du mot de passe
    mdp = "SuperMot2Passe!2024"
    hash_mdp = securiser_mdp(mdp)
    print("Hash bcrypt:", hash_mdp)
    print("Vérification OK ?", verifier_mdp(mdp, hash_mdp))
