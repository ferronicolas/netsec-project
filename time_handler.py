import time

VALID_THRESHOLD = 5  # In seconds


def is_timestamp_valid(mge_timestamp):
    current_time = time.time()  # In seconds
    if current_time >= (mge_timestamp + VALID_THRESHOLD):
        return False
    else:
        return True
