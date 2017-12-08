def check_length(list,expected_length):
    return len(list) is expected_length


def check_charset(data,charset):
    return not set(data).isdisjoint(set(charset))

