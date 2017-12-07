class Error(Exception):
    """
        Base class for other exceptions
    """
    pass


class InvalidIPAddressError(Error):
    """
        Raised when the IP is invalid
    """
    def __init__(self, message):
        self.message = message


class InvalidPortError(Error):
    """
        Raised when the port is invalid
    """

    def __init__(self, message):
        self.message = message

