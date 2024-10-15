from abc import ABC

from .utils.errs import FuzzyDooError


class DecodingError(FuzzyDooError):
    """Generic error for the `Decoder` interface."""


class Decoder(ABC):
    pass
