"""End-to-end GUI tests: real Tkinter widgets, real bound button callbacks.

Only the modal file-dialog and messagebox functions are monkeypatched, since
those block on user input and can't be scripted otherwise - this is the
standard way to drive a Tkinter app headlessly. Every call below goes through
the exact method a real button's `command=` is wired to, so a pass here means
the GUI itself produces the verdict, not just the underlying core/ codec.

Requires a reachable display (tk.Tk() must be able to connect) - skipped
automatically if none is available (e.g. a CI runner with no X server/Xvfb).
"""

import tempfile
from pathlib import Path
from unittest import mock

import pytest
from PIL import Image

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
PASSPHRASE = "INF2005-P1-6-demo"


def _display_available():
    try:
        import tkinter as tk

        root = tk.Tk()
        root.destroy()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _display_available(), reason="no reachable display for Tkinter")


@pytest.fixture
def app():
    import gui as gui_mod

    application = gui_mod.ACW1()
    application.update()
    yield application
    application.destroy()


def _verify(app, path, passphrase=None):
    import gui as gui_mod

    if passphrase is not None:
        app.passphrase_var.set(passphrase)
    with mock.patch.object(gui_mod.filedialog, "askopenfilename", return_value=str(path)):
        app.verify_file()
    return app.verdict_var.get()


def test_positive_image_authentic(app):
    assert _verify(app, SAMPLES / "stego_image_authentic.png", PASSPHRASE) == "AUTHENTIC"


def test_positive_audio_authentic(app):
    assert _verify(app, SAMPLES / "stego_audio_authentic.wav", PASSPHRASE) == "AUTHENTIC"


def test_tampered_image_is_tampered(app):
    assert _verify(app, SAMPLES / "stego_image_tampered.png", PASSPHRASE) == "TAMPERED"


def test_wrong_passphrase_audio_is_payload_missing(app):
    assert _verify(app, SAMPLES / "stego_audio_authentic.wav", "not-the-right-passphrase") == "PAYLOAD_MISSING"


def test_wrong_key_image_is_signature_invalid(app):
    assert _verify(app, SAMPLES / "stego_image_wrong_key.png", PASSPHRASE) == "SIGNATURE_INVALID"


def test_doctored_fixture_is_wrong_start_location(app):
    assert _verify(app, SAMPLES / "stego_image_wrong_start_location.png", PASSPHRASE) == "WRONG_START_LOCATION"


def test_plain_cover_is_payload_missing(app):
    assert _verify(app, SAMPLES / "cover.png", PASSPHRASE) == "PAYLOAD_MISSING"


def test_unreadable_file_is_cannot_verify(app, tmp_path):
    garbage = tmp_path / "not_really_a.png"
    garbage.write_bytes(b"not a real image file")
    assert _verify(app, garbage, PASSPHRASE) == "CANNOT_VERIFY"


def test_embed_button_then_verify_button_round_trip(app, tmp_path):
    import gui as gui_mod

    with mock.patch.object(gui_mod.filedialog, "askopenfilename", return_value=str(SAMPLES / "cover.png")):
        app.load_cover()
    app.lsb_var.set(3)
    app.passphrase_var.set("a-fresh-session-passphrase")

    out_path = tmp_path / "fresh_stego.png"
    with mock.patch.object(gui_mod.filedialog, "asksaveasfilename", return_value=str(out_path)):
        app.embed_payload()

    assert out_path.exists()
    assert app.start_location_var.get().isdigit()
    assert int(app.start_location_var.get()) > 0

    assert _verify(app, out_path) == "AUTHENTIC"


def _panel_hashes(app):
    lines = app.payload_text.get("1.0", "end").splitlines()
    embedded = lines[lines.index("Cover hash embedded at signing:") + 1]
    recomputed = lines[lines.index("Cover hash recomputed now:") + 1]
    return embedded, recomputed


def test_authentic_shows_payload_and_matching_hashes(app):
    assert _verify(app, SAMPLES / "stego_image_authentic.png", PASSPHRASE) == "AUTHENTIC"
    text = app.payload_text.get("1.0", "end")
    embedded, recomputed = _panel_hashes(app)
    assert len(embedded) == 64 and embedded == recomputed
    assert "Match: yes" in text
    assert '"team": "P1-6"' in text


def test_tampered_shows_payload_and_failed_hash_comparison(app):
    assert _verify(app, SAMPLES / "stego_image_tampered.png", PASSPHRASE) == "TAMPERED"
    text = app.payload_text.get("1.0", "end")
    embedded, recomputed = _panel_hashes(app)
    assert len(embedded) == 64 and len(recomputed) == 64 and embedded != recomputed
    assert "Match: NO" in text
    assert '"team": "P1-6"' in text


def test_signature_invalid_withholds_payload_and_explains_why(app):
    assert _verify(app, SAMPLES / "stego_image_wrong_key.png", PASSPHRASE) == "SIGNATURE_INVALID"
    text = app.payload_text.get("1.0", "end")
    assert "signature did not verify" in text
    assert "Cover hash" not in text
    assert "P1-6" not in text


def _load_cover(app, path):
    import gui as gui_mod

    with mock.patch.object(gui_mod.filedialog, "askopenfilename", return_value=str(path)):
        app.load_cover()


def test_message_typed_in_gui_is_recovered_exactly(app, tmp_path):
    import gui as gui_mod

    _load_cover(app, SAMPLES / "cover.png")
    app.passphrase_var.set("gui-message-test")
    message = "Line one — “smart quotes”, café\nsecond line\n\ttrailing spaces   "
    app.message_input.insert("1.0", message)

    out_path = tmp_path / "with_message.png"
    with mock.patch.object(gui_mod.filedialog, "asksaveasfilename", return_value=str(out_path)):
        app.embed_payload()

    assert _verify(app, out_path) == "AUTHENTIC"
    assert app.message_output.get("1.0", "end-1c") == message
    assert "trailing spaces" not in app.payload_text.get("1.0", "end")


def test_empty_message_shows_metadata_only_note(app):
    assert _verify(app, SAMPLES / "stego_image_authentic.png", PASSPHRASE) == "AUTHENTIC"
    assert "no message was embedded" in app.message_output.get("1.0", "end-1c")


def test_signature_invalid_withholds_message(app):
    assert _verify(app, SAMPLES / "stego_image_wrong_key.png", PASSPHRASE) == "SIGNATURE_INVALID"
    assert "withheld" in app.message_output.get("1.0", "end-1c")


def test_message_size_label_tracks_message_and_lsb(app):
    _load_cover(app, SAMPLES / "cover.png")  # 600x600 -> 1,080,000 carrier bytes
    assert "Fits" in app.message_size_var.get()

    app.message_input.insert("1.0", "x" * 80000)
    app.update()
    assert "May not fit" in app.message_size_var.get()

    app.message_input.insert("end", "x" * 120000)
    app.update()
    assert "Too large" in app.message_size_var.get()

    app.lsb_var.set(8)
    assert "Fits" in app.message_size_var.get()


def test_cover_picker_offers_no_jpeg(app):
    import gui as gui_mod

    with mock.patch.object(gui_mod.filedialog, "askopenfilename", return_value="") as dialog:
        app.load_cover()
    patterns = " ".join(pattern for _, pattern in dialog.call_args.kwargs["filetypes"]).lower()
    assert "jpg" not in patterns and "jpeg" not in patterns and "*.*" not in patterns


def test_jpeg_cover_rejected_at_load(app, tmp_path):
    import gui as gui_mod

    jpeg_path = tmp_path / "disguised_jpeg.png"
    Image.new("RGB", (64, 64), color=(10, 20, 30)).save(jpeg_path, format="JPEG")
    with mock.patch.object(gui_mod.filedialog, "askopenfilename", return_value=str(jpeg_path)):
        with mock.patch.object(gui_mod.messagebox, "showerror") as mock_error:
            app.load_cover()

    assert mock_error.called
    assert app.cover_path is None
    assert str(app.embed_button["state"]) == "disabled"


def test_oversized_payload_rejected_via_embed_button(app, tmp_path):
    import gui as gui_mod

    tiny_cover = tmp_path / "tiny.png"
    Image.new("RGB", (4, 4)).save(tiny_cover, format="PNG")
    with mock.patch.object(gui_mod.filedialog, "askopenfilename", return_value=str(tiny_cover)):
        app.load_cover()
    app.passphrase_var.set("whatever")

    out_path = tmp_path / "should_not_exist.png"
    with mock.patch.object(gui_mod.messagebox, "showerror") as mock_error:
        with mock.patch.object(gui_mod.filedialog, "asksaveasfilename", return_value=str(out_path)):
            app.embed_payload()
        assert mock_error.called

    assert not out_path.exists()


def test_play_button_degrades_gracefully_without_a_system_player(app):
    """Confirms the playback code path doesn't crash when no audio player
    binary is present (true in this dev sandbox - see the final report's
    caveat about actual sound output never being confirmed here).
    """
    import gui as gui_mod

    _verify(app, SAMPLES / "stego_audio_authentic.wav", PASSPHRASE)
    with mock.patch.object(gui_mod.shutil, "which", return_value=None):
        with mock.patch.object(gui_mod.messagebox, "showinfo") as mock_info:
            app.stego_play_button.invoke()
            assert mock_info.called
