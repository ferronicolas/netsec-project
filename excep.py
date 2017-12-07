class Error(Exception):
    """
        Base class for other exceptions
    """
    pass


class InvalidIPAddressError(Error):
    """
        Raised when the IP is invalid
    """
    pass


class InvalidPortError(Error):
    """
        Raised when the port is invalid
    """
    pass

