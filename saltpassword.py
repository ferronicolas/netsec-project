import os, hashlib, binascii


def compute(password):
    """
    Computes salt (64 bytes) and hash value with sha512
    :param password: input password
    :return: salt and hash value
    """
    salt = str(binascii.hexlify(os.urandom(4)))
    return salt, hashlib.sha512(salt + binascii.hexlify(password)).hexdigest()


def check(salt, password, has):
    """
    Checks if sha512(salt|password) == has
    :param salt:
    :param password:
    :param has:
    :return: True or False
    """
    return hashlib.sha512(str(salt) + binascii.hexlify(password)).hexdigest() == has
