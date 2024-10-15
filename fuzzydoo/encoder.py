from abc import ABC

from .utils.errs import FuzzyDooError


class EncodingError(FuzzyDooError):
    """Generic error for the `Encoder` interface."""


class Encoder(ABC):
    pass
