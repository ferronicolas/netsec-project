import time

ACCEPTED_THRESHOLD = 5  # In seconds


def is_timestamp_valid(mge_timestamp):
    current_time = time.time()  # In seconds
    if current_time >= (mge_timestamp + ACCEPTED_THRESHOLD):
        return False
    else:
        return True
