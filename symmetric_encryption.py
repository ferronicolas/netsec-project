# Base code gotten from the official site: https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#
# Modifications were done
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag
import binascii

# Global constants
IV_SIZE = 12  # NIST recommends a 96-bit IV length for performance critical situations


# Encrypt private
def encrypt_message_symmetric_key(key, plaintext, associated_data):
    # Generate a random 96-bit IV.
    iv = os.urandom(IV_SIZE)
    # Construct an AES-GCM Cipher object with the given key and a randomly generated IV.
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
    encryptor.authenticate_additional_data(associated_data)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag


# Encrypt public
def encrypt(shared_key, message, associated_data):
    iv, ciphertext, tag = encrypt_message_symmetric_key(shared_key, message, associated_data)
    return binascii.hexlify(iv) + " " + binascii.hexlify(associated_data) + " " + binascii.hexlify(tag) + " " + binascii.hexlify(ciphertext)


# Decrypt
def decrypt_message_symmetric_key(key, associated_data, iv, ciphertext, tag):
    # Construct a Cipher object, with the key, iv, and additionally the GCM tag used for authenticating the message
    try:
        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
        decryptor.authenticate_additional_data(associated_data)
        return decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag:
        print "Invalid tag"
        return None


def decrypt(shared_key, message):
    iv = binascii.unhexlify(message[0])
    associated_data = binascii.unhexlify(message[1])
    tag = binascii.unhexlify(message[2])
    ciphertext = binascii.unhexlify(message[3])
    return decrypt_message_symmetric_key(shared_key, associated_data, iv, ciphertext, tag)


# random_data = os.urandom(128)
# what = os.urandom(32)
# iv, ciphertext, tag = encrypt_message_symmetric_key(what, "WHAT", random_data)
# print decrypt_message_symmetric_key(what, random_data, iv, ciphertext, tag)
