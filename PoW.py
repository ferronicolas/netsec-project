import hashlib, os, binascii


def proof_o_work(length_part1,length_part2):
    """
    :param length_part1: number of bytes/2 of the public random number
    :param length_part2: number of bytes/2 of the to be guessed random number
    :return: random_number1, random_number2, hash value: sha512(r1|r2)
    """
    #Goal let someone find r2 given r1 and sha256(r1||r2)
    r1 = binascii.hexlify(os.urandom(length_part1))
    r2 = binascii.hexlify(os.urandom(length_part2))
    r1 = r1 + r2[0:length_part2]  # divides gap between bytes by 2
    r2 = r2[length_part2:]        # divides gap between bytes by 2
    print r1, r2, hashlib.sha512(str(r1) + str(r2)).hexdigest()
    return r1, r2, hashlib.sha512(str(r1) + str(r2)).hexdigest()


def check_proof_o_work(r1,r2,hash_value):
    """
    checks if sha512(r1|r2) == hash_value
    :param r1: random number 1
    :param r2: random number 2
    :param hash_value:
    :return: true or false
    """
    return hash_value == hashlib.sha512(str(r1) + str(r2)).hexdigest()