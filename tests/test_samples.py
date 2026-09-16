"""Every committed stego fixture carries Learning Outcome 1 as its message - including the negative cases."""

from pathlib import Path

from core import audio_stego, bitstream, crypto, image_stego, location
from core import payload as payload_mod
from core.verdict import Verdict

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
KEYS = Path(__file__).resolve().parent.parent / "keys"
PASSPHRASE = "INF2005-P1-6-demo"
MESSAGE = "Explain how steganography can be used to embed hidden verification data in image and audio cover objects."


def _demo_a():
    return crypto.load_keypair(KEYS / "demo_a_pub.pem")


def _trusted():
    demo_a = _demo_a()
    return {demo_a.key_id: demo_a.public_key}


def _derived_start(codec, carrier, meta):
    if codec is audio_stego:
        cover_id = location.cover_id_for_audio(meta["sampwidth"], meta["n_channels"], meta["n_frames"])
    else:
        cover_id = location.cover_id_for_image(meta["width"], meta["height"])
    return location.derive_start(cover_id, PASSPHRASE, len(carrier))


def _read_body_directly(codec, path, start=None):
    """Decrypt whatever payload sits at start with the correct passphrase, ignoring the verdict."""
    carrier, meta = codec._load_carrier(path)
    if start is None:
        start = _derived_start(codec, carrier, meta)
    prefix = payload_mod.parse_prefix_bytes(bitstream.read_bits(carrier, start, payload_mod.PREFIX_LEN, 1))
    assert prefix.magic_ok, f"no payload at offset {start}"
    return payload_mod.parse_body(
        carrier, start + payload_mod.PREFIX_CARRIER_LEN, prefix.num_lsb, prefix.body_len, PASSPHRASE, _trusted()
    )


def test_positive_fixtures_recover_the_message():
    for codec, name in ((image_stego, "stego_image_authentic.png"), (audio_stego, "stego_audio_authentic.wav")):
        verdict, extracted = codec.decode(SAMPLES / name, PASSPHRASE, _trusted())
        assert verdict == Verdict.AUTHENTIC
        assert extracted.payload["message"] == MESSAGE


def test_tampered_fixture_still_recovers_the_message():
    verdict, extracted = image_stego.decode(SAMPLES / "stego_image_tampered.png", PASSPHRASE, _trusted())
    assert verdict == Verdict.TAMPERED
    assert extracted.payload["message"] == MESSAGE


def test_wrong_passphrase_hides_a_message_that_is_really_there():
    path = SAMPLES / "stego_audio_authentic.wav"
    verdict, extracted = audio_stego.decode(path, "not-the-right-passphrase", _trusted())
    assert verdict == Verdict.PAYLOAD_MISSING and extracted is None
    assert _read_body_directly(audio_stego, path).parsed["message"] == MESSAGE


def test_wrong_key_fixture_withholds_a_message_that_is_really_there():
    path = SAMPLES / "stego_image_wrong_key.png"
    verdict, extracted = image_stego.decode(path, PASSPHRASE, _trusted())
    assert verdict == Verdict.SIGNATURE_INVALID and extracted is None

    body = _read_body_directly(image_stego, path)
    assert body.verified_key_id is None
    assert body.parsed["message"] == MESSAGE


def test_wrong_start_location_fixture_holds_a_real_signed_payload_at_offset_zero():
    path = SAMPLES / "stego_image_wrong_start_location.png"
    verdict, extracted = image_stego.decode(path, PASSPHRASE, _trusted())
    assert verdict == Verdict.WRONG_START_LOCATION and extracted is None

    body = _read_body_directly(image_stego, path, start=0)
    assert body.verified_key_id == _demo_a().key_id
    assert body.parsed["message"] == MESSAGE
