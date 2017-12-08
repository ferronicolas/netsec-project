from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.exceptions import InvalidSignature
import base64

# Global constants
INVALID_SIGNATURE = "Invalid signature"
ERROR_WHEN_VERIFYING_SIGNATURE = "Error when verifying signature"

# def convert_from_characters_to_bits(string):
#     return bin(int(binascii.hexlify(string), 16))
#
#
# def convert_from_bits_to_characters(string):
#     n = int(string, 2)
#     return binascii.unhexlify('%x' % n)


# Gets public key based on the given filename
def get_public_key(public_key_filename):
    with open(public_key_filename, "rb") as key_file:
        public_key = serialization.load_der_public_key(key_file.read(), backend=default_backend())
    key_file.close()
    return public_key


# Gets private key based on the given filename
def get_private_key(private_key_filename):
    with open(private_key_filename, "rb") as key_file:
        private_key = serialization.load_der_private_key(key_file.read(), password=None, backend=default_backend())
    key_file.close()
    return private_key


# Encrypts message with public key
def encrypt_message(public_key_filename, message):
    public_key = get_public_key(public_key_filename)
    ciphertext = public_key.encrypt(message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    base64.b64encode(ciphertext)
    return ciphertext


# Decrypts message with private key
def decrypt_message(private_key_filename, ciphertext):
    base64.b64decode(ciphertext)
    private_key = get_private_key(private_key_filename)
    message = private_key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return message


# Signs message given the private key and the message to sign
def sign_message(private_key_filename, message):
    private_key = get_private_key(private_key_filename)
    chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash, default_backend())
    message_splitted = [message[i: i + 100] for i in range(0, len(message), 100)]
    for part in message_splitted:
        hasher.update(part)
    digest = hasher.finalize()
    signature = private_key.sign(digest, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), utils.Prehashed(chosen_hash))
    return signature


# Verifies signature given the public key filename, the signature (gotten with the sign_message method)
# and the message of which the signature needs to be verified (for the hashing calculation)
def verify_signature(public_key_filename, signature, message_to_verify_signature_of):
    public_key = get_public_key(public_key_filename)
    chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash, default_backend())
    message_splitted = [message_to_verify_signature_of[i: i + 100] for i in range(0, len(message_to_verify_signature_of), 100)]
    for part in message_splitted:
        hasher.update(part)
    digest = hasher.finalize()
    try:
        public_key.verify(signature, digest, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), utils.Prehashed(chosen_hash))
        return True
    except InvalidSignature:
        print INVALID_SIGNATURE
        return False
    except Exception:
        print ERROR_WHEN_VERIFYING_SIGNATURE
        return False

MESSAGE = "asfklansflkanslkasklfnaslkssakfnlsaknflasflkansaksnfasnfklanfslkasnlkfnaakansflkansaksnfasnfklanfslkasnlkfnasklanlknklfnasklnflkasnfklanskflasflkasnfklanskflasakansflkansaksnfasnfklanfslkasnlkfnasklanlknklfnasklnflkasnfklanskflasakansflkansaksnfasnfklanfslkasnlkfnasklanlknklfnasklnflkasnfklanskflasakansflkansaksnfasnfklanfslkasnlkfnasklanlknklfnasklnflkasnfklanskflasakansflkansaksnfasnfakansflkansaksnfasnfklanfslkasnlkfnasklanlknklfnasklnflkasnfklanskflasakansflkansaksnfasnfklanfslkasnlkfnasklanlknklfnasklnflkasnfklanskflasakansflkansaksnfasnfklanfslkasnlkfnasklanlknklfnasklnflkasnfklanskflasklanfslkasnlkfnasklanlknklfnasklnflkasnfklanskflasnklfnalknskklsnfklasnaklsnfklasnaklsnfklasnaklsnfklasnaklsnfklasnaklsnfklasnaklsnfklasnaklsnfklasnaklsnfklasnaklsnfklasnaklsnfklasnaklsnfklasnaklsnfklasnaklsnfklasnaklsnfklasnaklsnfklasnaklsnfklasnaklsnfklasnaklsnfklasnaklsnfklasnaklsnfklasnaklsnfklasnaklsnfklasnaklsnfklasnaklsnfklasnaklsnfklasnaklsnfklasn"
# 446 MAX PERMITTED
if __name__ == "__main__":
    cipher = encrypt_message("public_key_8192.der", MESSAGE)
    message = decrypt_message("private_key_8192.der", cipher)
    print message
    print len(message)
    print "Identical: " + str(message == MESSAGE)
    # signature = sign_message("private_key_4096.der", MESSAGE)
    # result = verify_signature("public_key_4096.der", signature, MESSAGE)
    # print result

