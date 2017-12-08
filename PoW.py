import hashlib, os, binascii,math
import itertools, hashlib


# Goal let someone find r2 given r1 and sha256(r1||r2)
def proof_o_work(length_part2):
    """
    :param length_part1: number of bytes/2 of the public random number
    :param length_part2: number of bytes/2 of the to be guessed random number
    :return: random_number1, random_number2, hash value: sha512(r1|r2)

The following code is a work around the PoW. Since us.random generates random bytes this creates large
jumps in computational time. (2 bytes = 1 second, 3 bytes = 30 seconds). By dividing 1000 over m, the
larger m gets, the smaller 1000/m gets, so the computational jump will be less big.
    """
    length_part1 = int(math.floor(1000/length_part2))
    r1 = binascii.hexlify(os.urandom(length_part1))
    r2 = binascii.hexlify(os.urandom(length_part2))
    r1 = r1 + r2[0:length_part2]  # divides gap between bytes by 2
    r2 = r2[length_part2:]        # divides gap between bytes by 2
    return r1, r2, hashlib.sha512(str(r1) + str(r2)).hexdigest()


def check_proof_o_work(r1, r2, hash_value):
    """
    checks if sha512(r1|r2) == hash_value
    :param r1: random number 1
    :param r2: random number 2
    :param hash_value:
    :return: true or false
    """
    return hash_value == hashlib.sha512(str(r1) + str(r2)).hexdigest()



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
    return 0
