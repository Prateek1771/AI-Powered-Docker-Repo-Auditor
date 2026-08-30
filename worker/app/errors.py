class PermanentFailure(Exception):
    """Raised when retrying cannot help: bad input, missing image, 4xx."""
