# wallet.py
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

def generate_keys():
    """
    Generate a new RSA public-private key pair.
    Note: In production, you'd typically use ECC for blockchain wallets,
    but for simplicity, we use RSA here.
    """
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key.decode('utf-8'), public_key.decode('utf-8')

def encrypt_private_key(private_key, password):
    """
    Encrypt the private key with a password.
    (Basic encryption example - for learning purposes)
    """
    cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
    encrypted_key = cipher.encrypt(password.encode())
    return binascii.hexlify(encrypted_key).decode('utf-8')
