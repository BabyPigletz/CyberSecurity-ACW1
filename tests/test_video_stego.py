from pathlib import Path
from unittest import mock

from core import video_stego
from core.verdict import Verdict


def test_video_dsss_encode_delegates_to_audio_and_remuxes(tmp_path):
    source = tmp_path / "cover.mkv"
    target = tmp_path / "stego.mkv"
    source.write_bytes(b"video")
    keypair = object()

    with mock.patch.object(video_stego, "_require_ffmpeg"), \
            mock.patch.object(video_stego, "_has_audio_stream", return_value=True), \
            mock.patch.object(video_stego, "_extract_audio_to_wav") as extract, \
            mock.patch.object(video_stego, "_remux_video_with_audio") as remux, \
            mock.patch.object(video_stego.audio_stego, "encode_dsss", return_value=123) as encode:
        result = video_stego.encode_dsss(
            source, target, {"message": "hello"}, "passphrase", keypair, chip_length=64
        )

    assert result == 123
    extract.assert_called_once()
    encode.assert_called_once()
    remux.assert_called_once_with(source, mock.ANY, target)


def test_video_dsss_decode_delegates_to_audio(tmp_path):
    source = tmp_path / "stego.mkv"
    source.write_bytes(b"video")
    trusted_keys = {"demo": object()}
    expected = (Verdict.AUTHENTIC, object())

    with mock.patch.object(video_stego, "_require_ffmpeg"), \
            mock.patch.object(video_stego, "_has_audio_stream", return_value=True), \
            mock.patch.object(video_stego, "_extract_audio_to_wav"), \
            mock.patch.object(video_stego.audio_stego, "decode_dsss", return_value=expected) as decode:
        result = video_stego.decode_dsss(
            source, "passphrase", trusted_keys, chip_length=64, expected_bytes_len=42
        )

    assert result == expected
    decode.assert_called_once()