"""Shared exception types used across core/ modules.

Kept separate from bitstream.py and location.py so neither has to import the
other just to raise the same error.
"""


class CapacityError(Exception):
    """Raised when data will not fit in the available carrier bytes."""


class UnsupportedFormatError(Exception):
    """Raised when a cover file's format is not supported for embedding."""


class ECCError(Exception):
    """Raised when Reed-Solomon error correction cannot recover payload data."""
