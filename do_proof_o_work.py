import itertools, hashlib


def compute_r2(r1,hash_value):
    """

    :param r1: first part of the hash input
    :param hash_value: output of the hash function sha512(r1|r2)
    :return: second part of the hash input
    """
    chars = "abcdef0123456789"
    r2 = '0'
    count = 1
    while True:
        for item in itertools.product(chars, repeat=count):
            r2 = ("".join(item))
            if hashlib.sha512(str(r1) + str(r2)).hexdigest() == hash_value:
                return r2
        count += 1

