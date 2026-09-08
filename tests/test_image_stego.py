import os
import tempfile
from pathlib import Path

import pytest
from PIL import Image

from core import crypto, image_stego
from core.errors import CapacityError
from core.verdict import Verdict

KEYS = Path(__file__).resolve().parent.parent / "keys"


def _keys():
    demo_a = crypto.load_keypair(KEYS / "demo_a_pub.pem", KEYS / "demo_a_priv.pem")
    demo_b = crypto.load_keypair(KEYS / "demo_b_pub.pem")
    return demo_a, demo_b


@pytest.fixture
def cover_png(tmp_path):
    img = Image.new("RGB", (128, 128))
    px = img.load()
    for y in range(128):
        for x in range(128):
            px[x, y] = ((x * 2) % 256, (y * 2) % 256, (x + y) % 256)
    path = tmp_path / "cover.png"
    img.save(path, format="PNG")
    return path


def test_capacity_bytes_matches_formula(cover_png):
    img = Image.open(cover_png)
    assert image_stego.capacity_bytes(img, num_lsb=1) == (128 * 128 * 3 * 1) // 8
    assert image_stego.capacity_bytes(img, num_lsb=8) == (128 * 128 * 3 * 8) // 8


def test_encode_decode_round_trip_authentic(cover_png, tmp_path):
    demo_a, _ = _keys()
    trusted = {demo_a.key_id: demo_a.public_key}
    stego_path = tmp_path / "stego.png"

    start = image_stego.encode(cover_png, stego_path, {"meta": {"team": "P1-6"}}, "hunter2", demo_a, num_lsb=2)
    assert start > 0

    verdict, parsed = image_stego.decode(stego_path, "hunter2", trusted)
    assert verdict == Verdict.AUTHENTIC
    assert parsed["meta"]["team"] == "P1-6"


def test_jpeg_cover_accepted_output_always_png(tmp_path):
    """§2 allows loading a JPEG *cover* (decoded to RGB, re-saved as PNG) - it
    only forbids saving the *stego output* as JPEG. _save_carrier always
    writes PNG regardless of out_path's extension, so this is enforced
    structurally rather than by rejecting JPEG inputs.
    """
    demo_a, _ = _keys()
    trusted = {demo_a.key_id: demo_a.public_key}
    img = Image.new("RGB", (128, 128), color=(10, 20, 30))
    jpeg_path = tmp_path / "cover.jpg"
    img.save(jpeg_path, format="JPEG", quality=95)
    out_path = tmp_path / "out.png"

    image_stego.encode(jpeg_path, out_path, {}, "hunter2", demo_a, num_lsb=1)
    assert Image.open(out_path).format == "PNG"

    verdict, _ = image_stego.decode(out_path, "hunter2", trusted)
    assert verdict == Verdict.AUTHENTIC


def test_oversized_payload_rejected_before_writing(tmp_path):
    demo_a, _ = _keys()
    tiny = Image.new("RGB", (4, 4))
    tiny_path = tmp_path / "tiny.png"
    tiny.save(tiny_path, format="PNG")
    with pytest.raises(CapacityError):
        image_stego.encode(tiny_path, tmp_path / "out.png", {}, "hunter2", demo_a, num_lsb=1)
    assert not (tmp_path / "out.png").exists()


def test_tampered_pixel_after_embed_is_tampered(cover_png, tmp_path):
    demo_a, _ = _keys()
    trusted = {demo_a.key_id: demo_a.public_key}
    stego_path = tmp_path / "stego.png"
    image_stego.encode(cover_png, stego_path, {}, "hunter2", demo_a, num_lsb=2)

    img = Image.open(stego_path)
    img = img.convert("RGB")
    px = img.load()
    # Flip a bit above num_lsb (bit 7, well outside the 2 low bits used for
    # payload data) on an arbitrary pixel - changes canonical_hash regardless
    # of whether this carrier byte happens to fall within the payload's own
    # range, without corrupting the extractable payload itself.
    r, g, b = px[0, 0]
    px[0, 0] = (r ^ 0b10000000, g, b)
    img.save(stego_path, format="PNG")

    verdict, parsed = image_stego.decode(stego_path, "hunter2", trusted)
    assert verdict == Verdict.TAMPERED
    assert parsed is None
