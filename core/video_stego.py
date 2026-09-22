"""
Design: video frames are NOT touched. We extract the video's audio track to
uncompressed PCM WAV, run it through the existing, already-tested
core/audio_stego.py unchanged, then remix the stego WAV back together with
the original (untouched, stream-copied) video track.
 
Why not embed into frame pixels instead: consumer video codecs (H.264, VP9,
etc.) are lossy and re-encoding on save destroys LSB changes; embedding
losslessly would require re-muxing into a lossless codec (FFV1/raw), which
inflates file size dramatically and is a materially bigger, riskier scope
than the mandatory image/audio work. Audio-track embedding gets a genuine
third cover object with near-zero new crypto/format surface to get wrong.
 
Hence this innovation verifies the integrity of the video's AUDIO TRACK only. 
The visual frames are copied bit-for-bit but are NOT covered by the payload's 
cover_hash, so a frame-only tamper (splicing in a different visual track 
while keeping the original audio) would not be caught by this scheme. 
"""


import shutil
import subprocess
import tempfile
from pathlib import Path
 
from core import audio_stego
from core.crypto import KeyPair
from core.errors import UnsupportedFormatError
 
 
def _require_ffmpeg() -> None:
    if shutil.which("ffmpeg") is None or shutil.which("ffprobe") is None:
        raise UnsupportedFormatError(
            "ffmpeg/ffprobe not found on PATH - required for video cover objects. "
            "Install ffmpeg and ensure it is on PATH (see README)."
        )
 
 
def _has_audio_stream(path: Path) -> bool:
    result = subprocess.run(
        ["ffprobe", "-v", "error", "-select_streams", "a",
         "-show_entries", "stream=index", "-of", "csv=p=0", str(path)],
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip() != ""
 
 
def _extract_audio_to_wav(video_path: Path, wav_path: Path) -> None:
    subprocess.run(
        ["ffmpeg", "-y", "-i", str(video_path), "-vn",
         "-acodec", "pcm_s16le", str(wav_path)],
        capture_output=True, check=True,
    )
 
 
def _remux_video_with_audio(orig_video: Path, stego_wav: Path, out_path: Path) -> None:
    # -c:v copy: video stream is bit-for-bit untouched (no re-encode = no
    # frame-level quality loss and no risk of destroying anything).
    # -c:a copy on a WAV source keeps the PCM samples we just wrote intact -
    # the output container MUST support PCM audio (use .mkv or .avi; do not
    # use .mp4, whose ISO base media spec does not carry raw lpcm reliably
    # across players).
    if out_path.suffix.lower() not in (".mkv", ".avi"):
        raise UnsupportedFormatError(
            f"Output container '{out_path.suffix}' cannot reliably carry PCM "
            "audio without re-encoding (which would destroy the embedded "
            "payload). Use .mkv or .avi for the stego video."
        )
    # No -shortest: that flag trims to the SHORTER stream, which can clip
    # the embedded audio if its duration differs from the video's by even a
    # fraction of a second - silently truncating (and breaking) the payload.
    subprocess.run(
        ["ffmpeg", "-y", "-i", str(orig_video), "-i", str(stego_wav),
         "-map", "0:v:0", "-map", "1:a:0",
         "-c:v", "copy", "-c:a", "copy", str(out_path)],
        capture_output=True, check=True,
    )
 
 
def carrier_len(path: Path) -> int:
    """Raw carrier byte count of the video's audio track (LSB-independent -
    mirrors image_stego.carrier_len / audio_stego.carrier_len so the GUI can
    recompute capacity live as the LSB spinbox changes, same as the other
    two cover types)."""
    _require_ffmpeg()
    if not _has_audio_stream(path):
        raise UnsupportedFormatError("Video has no audio track to embed into.")
    with tempfile.TemporaryDirectory() as tmp:
        wav_path = Path(tmp) / "extracted.wav"
        _extract_audio_to_wav(path, wav_path)
        return audio_stego.carrier_len(wav_path)
 
 
def capacity_bytes(path: Path, num_lsb: int = 1) -> int:
    _require_ffmpeg()
    if not _has_audio_stream(path):
        raise UnsupportedFormatError("Video has no audio track to embed into.")
    with tempfile.TemporaryDirectory() as tmp:
        wav_path = Path(tmp) / "extracted.wav"
        _extract_audio_to_wav(path, wav_path)
        return audio_stego.capacity_bytes(wav_path, num_lsb)
 
 
def encode(in_path: Path, out_path: Path, payload_fields: dict,
           passphrase: str, keypair: KeyPair, num_lsb: int) -> int:
    """Embed into `in_path`'s audio track; write a new video to `out_path`
    (.mkv or .avi). Returns the derived start offset, same as audio_stego."""
    _require_ffmpeg()
    if not _has_audio_stream(in_path):
        raise UnsupportedFormatError("Video has no audio track to embed into.")
    with tempfile.TemporaryDirectory() as tmp:
        extracted_wav = Path(tmp) / "extracted.wav"
        stego_wav = Path(tmp) / "stego.wav"
        _extract_audio_to_wav(in_path, extracted_wav)
        offset = audio_stego.encode(
            extracted_wav, stego_wav, payload_fields, passphrase, keypair, num_lsb
        )
        _remux_video_with_audio(in_path, stego_wav, out_path)
    return offset
 
 
def decode(path: Path, passphrase: str, trusted_keys: dict):
    """Extract the payload from a stego video's audio track. Returns the
    same result object as audio_stego.decode (verdict, payload, etc.)."""
    _require_ffmpeg()
    if not _has_audio_stream(path):
        raise UnsupportedFormatError("Video has no audio track to extract from.")
    with tempfile.TemporaryDirectory() as tmp:
        wav_path = Path(tmp) / "extracted.wav"
        _extract_audio_to_wav(path, wav_path)
        return audio_stego.decode(wav_path, passphrase, trusted_keys)
 
 
def _load_carrier(path: Path):
    """Mirrors image_stego._load_carrier / audio_stego._load_carrier's shape
    (carrier bytes + meta) so callers like steganalysis comparison can treat
    a video exactly like the other two cover types, without knowing it's
    secretly an audio-track extraction underneath."""
    _require_ffmpeg()
    if not _has_audio_stream(path):
        raise UnsupportedFormatError("Video has no audio track.")
    with tempfile.TemporaryDirectory() as tmp:
        wav_path = Path(tmp) / "extracted.wav"
        _extract_audio_to_wav(path, wav_path)
        return audio_stego._load_carrier(wav_path)
 