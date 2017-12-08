import time

VALID_THRESHOLD = 5  # In seconds
EXPIRATION_PUZZLE = 10 * 60


def get_current_timestamp():
    return time.time()


def get_expiration_of_puzzle():
    return time.time() + EXPIRATION_PUZZLE


def is_timestamp_valid(mge_timestamp):
    current_time = time.time()  # In seconds
    if current_time >= (mge_timestamp + VALID_THRESHOLD):
        return False
    else:
        return True
