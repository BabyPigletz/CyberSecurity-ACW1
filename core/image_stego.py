"""
LSB Replacement Steganography for image cover objects (PNG Basic image)

TODO:
- encode -> stego_image
- decode -> Payload_bytes
- capacity check
"""

from PIL import Image

def capacity_bytes(image: Image.Image, num_lsb: int = 1) -> int:
    # Rough max payload size (bytes) this image can hold at num_lsb bits/channel
    width, height = image.size
    channels = len(image.mode) if image.mode != "P" else 1
    return (width * height * channels * num_lsb) // 8

def encode(image: Image.Image, payload: bytes, num_lsb: int = 1, start_location: int = 0) -> Image.Image:
    raise NotImplementedError

def decode(stego_image: Image.Image, num_lsb: int = 1, start_location: int = 0) -> bytes:
    raise NotImplementedError