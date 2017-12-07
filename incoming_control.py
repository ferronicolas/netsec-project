counter = 0

def main(length_proof_o_work):
    """
    function that increases the length of the proof o work if there if the function gets called too often.
    :param length_proof_o_work: current length of proof o work
    :return: updated length proof o work
    """
    global counter
    counter += 1
    if counter > 100:
        return length_proof_o_work + 1
    return length_proof_o_work

def reset():
    global counter
    counter = 0


