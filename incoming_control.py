counter = 0


def get_pow_length(length_proof_o_work):
    """
    Function that increases the length of the proof o work if there if the function gets called too often.
    :param length_proof_o_work: current length of proof o work
    :return: updated length proof o work
    """
    global counter
    counter += 1
    if counter > 10000:
        return length_proof_o_work + 1
    return length_proof_o_work


def reset():
    """
    Function that resets the counter to zero. Will be called every 30 seconds
    :return:
    """
    global counter
    counter = 0


def get_counter():
    print counter


