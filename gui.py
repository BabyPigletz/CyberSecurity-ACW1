"""
Tkinter GUI for Steganographic Image and Audio Integrity (ACW1)

Wires the LSB-replacement embed/extract pipeline in core/ to a GUI that can
load an image or WAV cover, embed a signed and encrypted payload (optionally
carrying a user-typed message) at a passphrase-derived (never user-chosen)
start location, and verify a file - own output or an externally supplied
sample - producing one of the six verdicts in docs/format.md §9.

Signing always uses the committed demo_a keypair; verification always trusts
demo_a's public key only (the assignment's default single-trusted-key model -
see README.md "Why encrypt-then-sign"). There is deliberately no key picker.
"""

import json
import shutil
import subprocess
import tkinter as tk
import wave
from pathlib import Path
from tkinter import filedialog, messagebox

from PIL import Image, ImageTk

from core import audio_stego, crypto, image_stego
from core import payload as payload_mod
from core.errors import CapacityError, UnsupportedFormatError
from core.verdict import Verdict

KEYS_DIR = Path(__file__).resolve().parent / "keys"
PAYLOAD_META = {"course": "INF2005", "team": "P1-6"}

VERDICT_COLORS = {
    Verdict.AUTHENTIC: "#1a7f37",
    Verdict.TAMPERED: "#c62828",
    Verdict.SIGNATURE_INVALID: "#c62828",
    Verdict.PAYLOAD_MISSING: "#b8860b",
    Verdict.WRONG_START_LOCATION: "#b8860b",
    Verdict.CANNOT_VERIFY: "#6a6a6a",
}


class ACW1(tk.Tk):
    ## Main application window
    THUMB_MAX_SIZE = (300, 300)

    def __init__(self):
        super().__init__()
        self.title("ACW1 (Steganography) - Lab P1 Group 6")
        self.geometry("1100x780")
        self.minsize(960, 700)

        ## App state
        self.cover_path: "Path | None" = None
        self.cover_carrier_len: "int | None" = None
        self.stego_path: "Path | None" = None
        self.active_kind: "str | None" = None  # "image" | "audio" - of whichever panel was last populated

        self._signer_keypair = crypto.load_keypair(KEYS_DIR / "demo_a_pub.pem", KEYS_DIR / "demo_a_priv.pem")
        self._trusted_keys = {self._signer_keypair.key_id: self._signer_keypair.public_key}

        self._build_menu()
        self._build_layout()

    ## UI construction
    def _build_menu(self):
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Open Cover...", command=self.load_cover)
        file_menu.add_command(label="Verify File...", command=self.verify_file)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        self.config(menu=menubar)

    def _build_layout(self):
        self.status_var = tk.StringVar(value="Ready.")
        tk.Label(self, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor="w").pack(
            side=tk.BOTTOM, fill=tk.X
        )

        # Right: embed-side controls (packed before the left side so it reserves its width)
        right_frame = tk.Frame(self, width=360)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=8, pady=8)
        right_frame.pack_propagate(False)
        self._build_controls(right_frame)

        # Left: verification result along the bottom, cover/stego previews above it
        left_frame = tk.Frame(self)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=8, pady=8)

        result_frame = tk.Frame(left_frame, bd=1, relief=tk.SUNKEN)
        result_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(8, 0))
        self._build_result_panel(result_frame)

        preview_frame = tk.Frame(left_frame)
        preview_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        self._build_preview_panel(preview_frame, "cover").pack(
            side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 4)
        )
        self._build_preview_panel(preview_frame, "stego").pack(
            side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(4, 0)
        )

    @staticmethod
    def _scrolled_text(parent, **options):
        frame = tk.Frame(parent)
        text = tk.Text(frame, **options)
        scrollbar = tk.Scrollbar(frame, command=text.yview)
        text.config(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        return frame, text

    def _build_preview_panel(self, parent, role: str):
        frame = tk.Frame(parent, bd=1, relief=tk.SUNKEN)
        title = "Cover" if role == "cover" else "Stego"
        tk.Label(frame, text=f"{title} Preview", font=("Segoe UI", 11, "bold")).pack(pady=(6, 0))

        image_label = tk.Label(frame, text="No file loaded", bg="#eeeeee")
        image_label.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        info_label = tk.Label(frame, text="", justify=tk.LEFT, anchor="w")
        info_label.pack(fill=tk.X, padx=10)

        play_button = tk.Button(frame, text="Play Audio", state=tk.DISABLED)
        play_button.pack(pady=(4, 8))

        setattr(self, f"{role}_image_label", image_label)
        setattr(self, f"{role}_info_label", info_label)
        setattr(self, f"{role}_play_button", play_button)
        return frame

    def _build_controls(self, right_frame):
        tk.Button(right_frame, text="Load Cover...", command=self.load_cover).pack(fill=tk.X, pady=(0, 10))

        tk.Label(right_frame, text="LSB Bits to Use (1-8)", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.lsb_var = tk.IntVar(value=1)
        tk.Spinbox(right_frame, from_=1, to=8, textvariable=self.lsb_var, width=5).pack(anchor="w", pady=(0, 10))
        self.lsb_var.trace_add("write", lambda *_: self._refresh_message_size())

        tk.Label(right_frame, text="Passphrase", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.passphrase_var = tk.StringVar()
        tk.Entry(right_frame, textvariable=self.passphrase_var, show="*").pack(fill=tk.X, pady=(0, 10))

        tk.Label(right_frame, text="Message to Hide (optional)", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        message_frame, self.message_input = self._scrolled_text(right_frame, height=8, width=36, wrap=tk.WORD, undo=True)
        message_frame.pack(fill=tk.X)
        self.message_input.bind("<<Modified>>", self._on_message_modified)

        self.message_size_var = tk.StringVar()
        tk.Label(
            right_frame, textvariable=self.message_size_var, fg="gray", justify=tk.LEFT, anchor="w", wraplength=340
        ).pack(fill=tk.X, pady=(2, 10))

        self.embed_button = tk.Button(
            right_frame, text="Embed Payload...", command=self.embed_payload, state=tk.DISABLED
        )
        self.embed_button.pack(fill=tk.X, pady=2)

        tk.Label(right_frame, text="Start Location (derived, read-only)", font=("Segoe UI", 10, "bold")).pack(
            anchor="w", pady=(10, 0)
        )
        self.start_location_var = tk.StringVar(value="-")
        tk.Label(right_frame, textvariable=self.start_location_var, fg="gray").pack(anchor="w", pady=(0, 10))

        tk.Button(right_frame, text="Verify File...", command=self.verify_file).pack(fill=tk.X, pady=2)

        self._refresh_message_size()

    def _build_result_panel(self, frame):
        header = tk.Frame(frame)
        header.pack(fill=tk.X, padx=10, pady=(6, 0))
        tk.Label(header, text="Verdict:", font=("Segoe UI", 11, "bold")).pack(side=tk.LEFT)
        self.verdict_var = tk.StringVar(value="—")
        self.verdict_label = tk.Label(header, textvariable=self.verdict_var, font=("Segoe UI", 13, "bold"))
        self.verdict_label.pack(side=tk.LEFT, padx=(6, 0))

        body = tk.Frame(frame)
        body.pack(fill=tk.BOTH, expand=True, padx=10, pady=(4, 10))
        body.columnconfigure(0, weight=3)
        body.columnconfigure(1, weight=2)

        tk.Label(body, text="Recovered Message", font=("Segoe UI", 11, "bold")).grid(row=0, column=0, sticky="w")
        tk.Label(body, text="Hash Check and Other Payload Fields", font=("Segoe UI", 10, "bold")).grid(
            row=0, column=1, sticky="w", padx=(10, 0)
        )
        message_frame, self.message_output = self._scrolled_text(
            body, height=7, width=40, wrap=tk.WORD, state=tk.DISABLED, font=("Segoe UI", 11), bg="#fffdf0"
        )
        message_frame.grid(row=1, column=0, sticky="nsew")
        details_frame, self.payload_text = self._scrolled_text(
            body, height=7, width=30, wrap=tk.WORD, state=tk.DISABLED
        )
        details_frame.grid(row=1, column=1, sticky="nsew", padx=(10, 0))

    ## Cover loading
    def load_cover(self):
        path = filedialog.askopenfilename(
            title="Select Cover Object",
            filetypes=[("Cover files", "*.png *.bmp *.wav")],
        )
        if not path:
            return
        path = Path(path)
        kind = "audio" if path.suffix.lower() == ".wav" else "image"

        try:
            if kind == "image":
                self._populate_image_panel("cover", path)
                carrier_len = image_stego.carrier_len(path)
            else:
                self._populate_audio_panel("cover", path)
                carrier_len = audio_stego.carrier_len(path)
        except Exception as exc:
            messagebox.showerror("Error loading cover", f"Could not open cover:\n{exc}")
            return

        self.cover_path = path
        self.cover_carrier_len = carrier_len
        self.active_kind = kind
        self.stego_path = None
        self._clear_preview_panel("stego")
        self.embed_button.config(state=tk.NORMAL)
        self._refresh_message_size()
        self.status_var.set(f"Loaded cover: {path.name}")

    def _populate_image_panel(self, role: str, path: Path):
        img = Image.open(path)
        if role == "cover" and img.format not in image_stego.SUPPORTED_FORMATS:
            raise UnsupportedFormatError(f"{img.format} covers are not supported - use PNG or BMP (lossless)")
        img.load()
        preview = img.copy()
        preview.thumbnail(self.THUMB_MAX_SIZE)
        tk_img = ImageTk.PhotoImage(preview)
        label = getattr(self, f"{role}_image_label")
        label.config(image=tk_img, text="")
        label.image = tk_img  # keep a reference so Tk doesn't garbage-collect it

        carrier_len = img.size[0] * img.size[1] * image_stego.CHANNELS
        getattr(self, f"{role}_info_label").config(
            text=f"{img.size[0]} x {img.size[1]} {img.format}\n{carrier_len:,} carrier bytes"
        )
        getattr(self, f"{role}_play_button").config(state=tk.DISABLED)

    def _populate_audio_panel(self, role: str, path: Path):
        with wave.open(str(path), "rb") as wf:
            n_channels, sampwidth = wf.getnchannels(), wf.getsampwidth()
            framerate, n_frames = wf.getframerate(), wf.getnframes()
        duration = n_frames / framerate if framerate else 0

        label = getattr(self, f"{role}_image_label")
        label.config(
            image="",
            text=f"WAV\n{n_channels}ch {sampwidth * 8}-bit\n{framerate} Hz, {duration:.1f}s",
        )
        label.image = None
        getattr(self, f"{role}_info_label").config(text=f"{audio_stego.carrier_len(path):,} carrier bytes")
        getattr(self, f"{role}_play_button").config(state=tk.NORMAL, command=lambda: self._play_audio(path))

    def _clear_preview_panel(self, role: str):
        label = getattr(self, f"{role}_image_label")
        label.config(image="", text="No file loaded")
        label.image = None
        getattr(self, f"{role}_info_label").config(text="")
        getattr(self, f"{role}_play_button").config(state=tk.DISABLED)
        if role == "stego":
            self.verdict_var.set("—")
            self.verdict_label.config(fg="black")
            self._set_text(self.message_output, "")
            self._set_text(self.payload_text, "")
            self.start_location_var.set("-")

    ## Message size / capacity
    def _message(self) -> str:
        return self.message_input.get("1.0", "end-1c")  # "end" would append a newline the user never typed

    def _on_message_modified(self, _event):
        if self.message_input.edit_modified():
            self._refresh_message_size()
            self.message_input.edit_modified(False)

    def _refresh_message_size(self):
        message = self._message()
        message_bytes = len(message.encode("utf-8"))
        body_len = payload_mod.estimate_body_len(message, PAYLOAD_META, self._signer_keypair)
        sizes = f"Message {message_bytes:,} bytes, payload {body_len:,} bytes."

        if self.cover_carrier_len is None:
            self.message_size_var.set(f"{sizes} Load a cover to check it fits.")
            return
        try:
            num_lsb = self.lsb_var.get()
        except (tk.TclError, ValueError):
            return  # spinbox mid-edit (e.g. briefly empty) - the next keystroke settles it

        carrier_len = self.cover_carrier_len
        # The derived start is anywhere in [0, carrier_len // 2), so capacity depends on the passphrase.
        guaranteed = payload_mod.max_body_len(carrier_len, max(carrier_len // 2 - 1, 0), num_lsb)
        best_case = payload_mod.max_body_len(carrier_len, 0, num_lsb)
        if body_len <= guaranteed:
            status = f"Fits: this cover holds at least {guaranteed:,} bytes at {num_lsb} LSB for any passphrase."
        elif body_len <= best_case:
            status = (
                f"May not fit: this cover holds {guaranteed:,}-{best_case:,} bytes at {num_lsb} LSB "
                "depending on the passphrase-derived start."
            )
        else:
            status = (
                f"Too large: this cover holds at most {best_case:,} bytes at {num_lsb} LSB. "
                "Use more LSBs, a larger cover, or a shorter message."
            )
        self.message_size_var.set(f"{sizes} {status}")

    ## Embed
    def embed_payload(self):
        if self.cover_path is None:
            return
        passphrase = self.passphrase_var.get()
        if not passphrase:
            messagebox.showwarning("Missing passphrase", "Enter a passphrase before embedding.")
            return
        num_lsb = self.lsb_var.get()

        if self.active_kind == "image":
            out_path = filedialog.asksaveasfilename(
                title="Save Stego Image As", defaultextension=".png", filetypes=[("PNG image", "*.png")]
            )
        else:
            out_path = filedialog.asksaveasfilename(
                title="Save Stego Audio As", defaultextension=".wav", filetypes=[("WAV audio", "*.wav")]
            )
        if not out_path:
            return
        out_path = Path(out_path)

        payload_fields = {"meta": PAYLOAD_META, "message": self._message()}
        try:
            if self.active_kind == "image":
                start = image_stego.encode(
                    self.cover_path, out_path, payload_fields, passphrase, self._signer_keypair, num_lsb
                )
            else:
                start = audio_stego.encode(
                    self.cover_path, out_path, payload_fields, passphrase, self._signer_keypair, num_lsb
                )
        except CapacityError as exc:
            messagebox.showerror("Payload too large", str(exc))
            return
        except Exception as exc:
            messagebox.showerror("Embed failed", str(exc))
            return

        self.start_location_var.set(str(start))
        try:
            if self.active_kind == "image":
                self._populate_image_panel("stego", out_path)
            else:
                self._populate_audio_panel("stego", out_path)
        except Exception as exc:
            messagebox.showerror("Error loading stego preview", str(exc))
            return

        self.stego_path = out_path
        self.status_var.set(f"Embedded -> {out_path.name} (derived start offset {start})")

    ## Verify
    def verify_file(self):
        path = filedialog.askopenfilename(
            title="Select File to Verify",
            filetypes=[("Cover/stego files", "*.png *.bmp *.wav"), ("All files", "*.*")],
        )
        if not path:
            return
        path = Path(path)
        passphrase = self.passphrase_var.get()
        kind = "audio" if path.suffix.lower() == ".wav" else "image"

        try:
            if kind == "image":
                verdict, extracted = image_stego.decode(path, passphrase, self._trusted_keys)
            else:
                verdict, extracted = audio_stego.decode(path, passphrase, self._trusted_keys)
        except Exception as exc:
            messagebox.showerror("Verify failed", str(exc))
            return

        self.active_kind = kind
        try:
            if kind == "image":
                self._populate_image_panel("stego", path)
            else:
                self._populate_audio_panel("stego", path)
        except Exception:
            pass  # preview is best-effort; the verdict below is what matters
        self.stego_path = path

        self.verdict_var.set(verdict.name)
        self.verdict_label.config(fg=VERDICT_COLORS.get(verdict, "black"))
        self._set_text(self.message_output, self._describe_message(verdict, extracted))
        self._set_text(self.payload_text, self._describe_extraction(verdict, extracted))
        self.status_var.set(f"Verified {path.name}: {verdict.name}")

    @staticmethod
    def _describe_message(verdict: Verdict, extracted) -> str:
        if extracted is not None:
            return extracted.payload.get("message") or "(no message was embedded - metadata-only payload)"
        if verdict == Verdict.SIGNATURE_INVALID:
            return "(withheld - the signature did not verify, so nothing recovered can be trusted)"
        return "(nothing recovered)"

    @staticmethod
    def _describe_extraction(verdict: Verdict, extracted) -> str:
        if extracted is not None:
            match = "yes" if extracted.cover_hash_matches else "NO - the carrier was altered after signing"
            other_fields = {key: value for key, value in extracted.payload.items() if key != "message"}
            return (
                f"Cover hash embedded at signing:\n{extracted.embedded_cover_hash or '(missing)'}\n\n"
                f"Cover hash recomputed now:\n{extracted.recomputed_cover_hash}\n\n"
                f"Match: {match}\n\n"
                f"Other payload fields:\n{json.dumps(other_fields, indent=2, sort_keys=True, ensure_ascii=False)}"
            )
        if verdict == Verdict.SIGNATURE_INVALID:
            return (
                "Nothing extracted is shown: the signature did not verify against the trusted key, "
                "so the payload and its cover hash cannot be trusted."
            )
        return "(no verified payload)"

    @staticmethod
    def _set_text(widget: tk.Text, text: str):
        widget.config(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, text)
        widget.config(state=tk.DISABLED)

    ## Audio playback
    def _play_audio(self, path: Path):
        player = shutil.which("paplay") or shutil.which("aplay")
        if not player:
            messagebox.showinfo(
                "Playback unavailable", "No system audio player (paplay/aplay) found in this environment."
            )
            return
        try:
            subprocess.Popen([player, str(path)])
        except Exception as exc:
            messagebox.showerror("Playback failed", str(exc))
