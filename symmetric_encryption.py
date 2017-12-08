# Base code gotten from the official site: https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#
# Modifications were done
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag

# Global constants
IV_SIZE = 12  # NIST recommends a 96-bit IV length for performance critical situations


# Encrypt
def encrypt(key, plaintext, associated_data):
    # Generate a random 96-bit IV.
    iv = os.urandom(IV_SIZE)
    # Construct an AES-GCM Cipher object with the given key and a randomly generated IV.
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
    encryptor.authenticate_additional_data(associated_data)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag


def decrypt(key, associated_data, iv, ciphertext, tag):
    # Construct a Cipher object, with the key, iv, and additionally the GCM tag used for authenticating the message
    try:
        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
        decryptor.authenticate_additional_data(associated_data)
        return decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag:
        print "Invalid tag"
        return None


# random_data = os.urandom(12345678)
# what = os.urandom(32)
# iv, ciphertext, tag = encrypt(what, "WHAT", random_data)
# decrypt(what, random_data, iv, ciphertext, tag)
