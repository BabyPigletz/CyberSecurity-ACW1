"""One-off script that builds the committed sample fixtures under samples/.

Run once from the repo root: `.venv/bin/python samples/generate_samples.py`.
Not part of the application - a build tool for demo material, kept here
(rather than deleted after running) so the fixtures are reproducible and the
reasoning behind the doctored ones is documented in one place, per the
project's decision to keep demo-fixture provenance auditable.

PASSPHRASE USED FOR ALL "authentic" SAMPLES BELOW: see samples/README.md.
"""

import os
import subprocess
import sys
import time
import uuid
import wave
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from media import audio_stego, image_stego

from PIL import Image
from cryptography.hazmat.primitives.asymmetric import rsa

from core import bitstream, crypto, payload as payload_mod, video_stego

SAMPLES_DIR = REPO_ROOT / "samples"
KEYS_DIR = REPO_ROOT / "keys"
PASSPHRASE = "INF2005-P1-6-demo"
NUM_LSB = 2
# Learning Outcome 1 from the assignment spec, verbatim. Every stego fixture carries it.
MESSAGE = "Explain how steganography can be used to embed hidden verification data in image and audio cover objects."


def make_cover_image() -> Path:
    path = SAMPLES_DIR / "cover.png"
    img = Image.new("RGB", (600, 600))
    px = img.load()
    for y in range(600):
        for x in range(600):
            px[x, y] = ((x * 3) % 256, (y * 3) % 256, ((x + y) * 2) % 256)
    img.save(path, format="PNG")
    return path


def make_cover_audio() -> Path:
    import math
    import struct

    path = SAMPLES_DIR / "cover.wav"
    framerate = 44100
    duration_s = 6
    n_frames = framerate * duration_s
    frames = bytearray()
    for i in range(n_frames):
        t = i / framerate
        # A simple two-tone signal, well within 16-bit range - audible and
        # deterministic, no external dependency (no numpy) needed.
        value = int(8000 * math.sin(2 * math.pi * 440 * t) + 4000 * math.sin(2 * math.pi * 660 * t))
        frames += struct.pack("<h", max(-32768, min(32767, value)))
    with wave.open(str(path), "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(framerate)
        wf.writeframes(bytes(frames))
    return path


def make_cover_video() -> Path:
    """A short, deterministic test-pattern clip with a tone audio track -
    built with ffmpeg (already a hard dependency of core/video_stego.py, so
    no new tooling requirement), same 6s duration as cover.wav so the "video
    cover objects use the same audio pipeline underneath" story is visible
    at a glance rather than just asserted.

    Audio is PCM (lossless), not AAC: a lossy codec's decoder can legitimately
    produce a different sample count on different machines/ffmpeg versions/
    builds (encoder-delay and priming-sample handling varies), which breaks
    reproducibility (FR12) even though nobody did anything wrong - confirmed
    the hard way when a student's re-extraction of an AAC cover came out 616
    bytes shorter than the one baked into this repo's committed stego file.
    PCM is a straight demux, not a decode, so it is bit-exact everywhere.
    Video stays H.264/MP4 - only picture quality, not reproducibility, is at
    stake there, and MP4 does not reliably carry PCM audio anyway (hence
    .mkv here, matching the stego output container)."""
    path = SAMPLES_DIR / "cover.mkv"
    subprocess.run(
        [
            "ffmpeg", "-y",
            "-f", "lavfi", "-i", "testsrc=size=320x240:rate=15:duration=6",
            "-f", "lavfi", "-i", "sine=frequency=440:duration=6:sample_rate=44100",
            "-c:v", "libx264", "-pix_fmt", "yuv420p",
            "-c:a", "pcm_s16le", "-shortest", str(path),
        ],
        capture_output=True, check=True,
    )
    return path


def main():
    SAMPLES_DIR.mkdir(exist_ok=True)
    demo_a = crypto.load_keypair(KEYS_DIR / "demo_a_pub.pem", KEYS_DIR / "demo_a_priv.pem")
    fields = {"meta": {"course": "INF2005", "team": "P1-6"}, "message": MESSAGE}

    cover_png = make_cover_image()
    cover_wav = make_cover_audio()
    cover_video = make_cover_video()
    print(f"wrote {cover_png}")
    print(f"wrote {cover_wav}")
    print(f"wrote {cover_video}")

    # --- Case 1/2: positive - AUTHENTIC (one per cover type) ---
    stego_png = SAMPLES_DIR / "stego_image_authentic.png"
    start_png = image_stego.encode(cover_png, stego_png, fields, PASSPHRASE, demo_a, NUM_LSB)
    print(f"wrote {stego_png} (start offset {start_png})")

    stego_wav = SAMPLES_DIR / "stego_audio_authentic.wav"
    start_wav = audio_stego.encode(cover_wav, stego_wav, fields, PASSPHRASE, demo_a, NUM_LSB)
    print(f"wrote {stego_wav} (start offset {start_wav})")

    # --- Case 3: negative - tampered pixel -> TAMPERED (image) ---
    tampered_path = SAMPLES_DIR / "stego_image_tampered.png"
    img = Image.open(stego_png).convert("RGB")
    px = img.load()
    r, g, b = px[0, 0]
    px[0, 0] = (r ^ 0b10000000, g, b)  # high bit, above NUM_LSB=2 - a visible-in-principle edit
    img.save(tampered_path, format="PNG")
    print(f"wrote {tampered_path} (bit 7 of pixel (0,0).R flipped after signing)")

    # --- Case 4: negative - wrong passphrase -> PAYLOAD_MISSING (audio) ---
    # No separate fixture: reuse stego_audio_authentic.wav, verified in the GUI
    # with a different passphrase. Decision (this session): a wrong passphrase
    # is the PAYLOAD_MISSING demo, not WRONG_START_LOCATION - the derived
    # offset almost never coincides with offset 0 by chance, so the honest,
    # natural result of a wrong passphrase is "no magic found anywhere we
    # looked", not "found elsewhere". See samples/README.md for the verify-time
    # passphrase to type.

    # --- Case 5: negative - wrong key -> SIGNATURE_INVALID (image) ---
    # demo_b's private key is deliberately not committed to the repo (see
    # keys/README.md). Generate a throwaway RSA-2048 keypair in memory here,
    # sign a sample with it, save only the resulting STEGO FILE, then let the
    # private key fall out of scope - nothing key-shaped ever touches disk.
    forged_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged_keypair = crypto.KeyPair(
        key_id=crypto._fingerprint(forged_private.public_key()),
        public_key=forged_private.public_key(),
        private_key=forged_private,
    )
    wrong_key_path = SAMPLES_DIR / "stego_image_wrong_key.png"
    image_stego.encode(cover_png, wrong_key_path, fields, PASSPHRASE, forged_keypair, NUM_LSB)
    print(f"wrote {wrong_key_path} (signed by a throwaway key the GUI's trusted set does not contain)")
    del forged_private, forged_keypair  # no private key material persists past this point

    # --- Extra: WRONG_START_LOCATION fixture (not one of the 5 demo cases, ---
    # --- but one of the 6 verdicts, and explicitly requested this session) ---
    # A complete, genuinely signed and encrypted payload (message included)
    # written at carrier offset 0, with nothing at the passphrase-derived
    # offset. This simulates a non-compliant tool that embedded from the first
    # byte - the one situation distinguishes from a plain, untouched cover
    # (PAYLOAD_MISSING). The normal embed flow always writes at the derived
    # offset and never at 0, so the payload is assembled and written directly
    # here. decode() reports WRONG_START_LOCATION as soon as it sees magic at 0
    # but not at the derived offset; it deliberately never reads a payload
    # from anywhere other than the derived offset.
    wrong_location_path = SAMPLES_DIR / "stego_image_wrong_start_location.png"
    carrier, meta = image_stego._load_carrier(cover_png)
    stray_payload = payload_mod.Payload(
        media_id=str(uuid.uuid4()),
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        nonce=os.urandom(16).hex(),
        meta=fields["meta"],
        cover_hash=crypto.canonical_hash(bytes(carrier), NUM_LSB),
        signer_key_id=demo_a.key_id,
        message=MESSAGE,
    )
    prefix, body = payload_mod.build_stego_bytes(stray_payload, PASSPHRASE, demo_a, NUM_LSB)
    bitstream.write_bits(carrier, 0, prefix, num_lsb=1)
    bitstream.write_bits(carrier, payload_mod.PREFIX_CARRIER_LEN, body, num_lsb=NUM_LSB)
    image_stego._save_carrier(wrong_location_path, carrier, meta)
    print(f"wrote {wrong_location_path} (doctored: full payload written at offset 0)")

    # --- Case 6 (innovation, optional §8): video cover object, positive - AUTHENTIC ---
    # Audio-track embedding (core/video_stego.py) - frames are stream-copied
    # untouched; only the extracted PCM audio is the carrier, exactly like
    # cover.wav above underneath.
    stego_video = SAMPLES_DIR / "stego_video_authentic.mkv"
    start_video = video_stego.encode(cover_video, stego_video, fields, PASSPHRASE, demo_a, NUM_LSB)
    print(f"wrote {stego_video} (start offset {start_video})")

    # --- Case 7 (innovation): video, negative - audio content tampered -> TAMPERED ---
    # Simple whole-file byte flips on an .mkv are unreliable (Matroska/EBML
    # container structure can absorb a flipped byte as metadata/padding
    # without touching the decoded audio samples at all) - so tampering is
    # done the same way a real attacker's tool would have to: extract the
    # audio, corrupt a PCM sample well past the header, remux into a new
    # video. Mirrors the audio wrong-passphrase case's honesty about what a
    # realistic attack on this format actually looks like.
    with __import__("tempfile").TemporaryDirectory() as tmp_dir:
        tmp_wav = Path(tmp_dir) / "extracted.wav"
        video_stego._extract_audio_to_wav(stego_video, tmp_wav)
        data = bytearray(tmp_wav.read_bytes())
        data[50000] ^= 0xFF
        tmp_wav.write_bytes(bytes(data))
        tampered_video_path = SAMPLES_DIR / "stego_video_tampered.mkv"
        video_stego._remux_video_with_audio(cover_video, tmp_wav, tampered_video_path)
    print(f"wrote {tampered_video_path} (one PCM byte flipped in the extracted audio track, then remuxed)")

    # --- Innovation limitation demo (not a graded case; deliberately shows ---
    # --- what this design does NOT catch, for the honest-limitations       ---
    # --- discussion (rubric criterion 7)). Splice the AUTHENTIC video's    ---
    # --- real, untouched, correctly-signed audio track onto visually      ---
    # --- altered frames. The payload's cover_hash covers audio samples     ---
    # --- only, so this verifies AUTHENTIC despite the visible frame edit - ---
    # --- show this live to make the "frames aren't covered" limitation    ---
    # --- concrete rather than just asserted in prose.
    frame_altered = SAMPLES_DIR / "_tmp_frame_altered.mp4"
    subprocess.run(
        ["ffmpeg", "-y", "-i", str(cover_video), "-vf", "eq=brightness=0.3",
         "-c:a", "copy", str(frame_altered)],
        capture_output=True, check=True,
    )
    with __import__("tempfile").TemporaryDirectory() as tmp_dir:
        tmp_wav = Path(tmp_dir) / "authentic_audio.wav"
        video_stego._extract_audio_to_wav(stego_video, tmp_wav)
        limitation_path = SAMPLES_DIR / "stego_video_frame_tampered_STILL_AUTHENTIC.mkv"
        video_stego._remux_video_with_audio(frame_altered, tmp_wav, limitation_path)
    frame_altered.unlink()
    print(f"wrote {limitation_path} (frames visibly altered, audio untouched - verifies AUTHENTIC: the stated cover-hash-is-audio-only limitation, made concrete)")

    print("\nDone. See samples/README.md for passphrases and expected verdicts.")


if __name__ == "__main__":
    main()