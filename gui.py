"""
Tkinter GUI for Steganographic Image and Audio Integrity (ACW1)

Wires the LSB-replacement embed/extract pipeline in core/ to a GUI that can
load an image or WAV cover, embed a signed and encrypted payload at a
passphrase-derived (never user-chosen) start location, and verify a file -
own output or an externally supplied sample - producing one of the six
verdicts in docs/format.md §9.

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
from core.errors import CapacityError, UnsupportedFormatError
from core.verdict import Verdict

KEYS_DIR = Path(__file__).resolve().parent / "keys"

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
        self.geometry("1040x700")
        self.minsize(900, 620)

        ## App state
        self.cover_path: "Path | None" = None
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
        # Right: controls (packed first so it reserves its width)
        right_frame = tk.Frame(self, width=340)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=8, pady=8)
        right_frame.pack_propagate(False)
        self._build_controls(right_frame)

        # Left: side-by-side cover/stego previews
        preview_frame = tk.Frame(self)
        preview_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=8, pady=8)

        self._build_preview_panel(preview_frame, "cover").pack(
            side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 4)
        )
        self._build_preview_panel(preview_frame, "stego").pack(
            side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(4, 0)
        )

        # Status bar
        self.status_var = tk.StringVar(value="Ready.")
        tk.Label(self, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor="w").pack(
            side=tk.BOTTOM, fill=tk.X
        )

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
        self.lsb_var.trace_add("write", lambda *_: self._refresh_cover_capacity())

        tk.Label(right_frame, text="Passphrase", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.passphrase_var = tk.StringVar()
        tk.Entry(right_frame, textvariable=self.passphrase_var, show="*").pack(fill=tk.X, pady=(0, 10))

        tk.Label(right_frame, text="Start Location (derived, read-only)", font=("Segoe UI", 10, "bold")).pack(
            anchor="w"
        )
        self.start_location_var = tk.StringVar(value="-")
        tk.Label(right_frame, textvariable=self.start_location_var, fg="gray").pack(anchor="w", pady=(0, 10))

        tk.Label(right_frame, text="Actions", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(6, 4))
        self.embed_button = tk.Button(
            right_frame, text="Embed Payload...", command=self.embed_payload, state=tk.DISABLED
        )
        self.embed_button.pack(fill=tk.X, pady=2)
        tk.Button(right_frame, text="Verify File...", command=self.verify_file).pack(fill=tk.X, pady=2)

        tk.Label(right_frame, text="Verdict", font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(16, 2))
        self.verdict_var = tk.StringVar(value="—")
        self.verdict_label = tk.Label(right_frame, textvariable=self.verdict_var, font=("Segoe UI", 13, "bold"))
        self.verdict_label.pack(anchor="w")

        self.payload_text = tk.Text(right_frame, height=10, width=36, state=tk.DISABLED, wrap=tk.WORD)
        self.payload_text.pack(fill=tk.BOTH, expand=True, pady=(6, 0))

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
            else:
                self._populate_audio_panel("cover", path)
        except Exception as exc:
            messagebox.showerror("Error loading cover", f"Could not open cover:\n{exc}")
            return

        self.cover_path = path
        self.active_kind = kind
        self.stego_path = None
        self._clear_preview_panel("stego")
        self.embed_button.config(state=tk.NORMAL)
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

        cap = image_stego.capacity_bytes(img, num_lsb=self.lsb_var.get())
        getattr(self, f"{role}_info_label").config(
            text=f"{img.size[0]} x {img.size[1]} {img.format}\ncapacity @ {self.lsb_var.get()} LSB: {cap:,} bytes"
        )
        getattr(self, f"{role}_play_button").config(state=tk.DISABLED)

    def _populate_audio_panel(self, role: str, path: Path):
        with wave.open(str(path), "rb") as wf:
            n_channels, sampwidth = wf.getnchannels(), wf.getsampwidth()
            framerate, n_frames = wf.getframerate(), wf.getnframes()
        duration = n_frames / framerate if framerate else 0
        cap = audio_stego.capacity_bytes(path, num_lsb=self.lsb_var.get())

        label = getattr(self, f"{role}_image_label")
        label.config(
            image="",
            text=f"WAV\n{n_channels}ch {sampwidth * 8}-bit\n{framerate} Hz, {duration:.1f}s",
        )
        label.image = None
        getattr(self, f"{role}_info_label").config(
            text=f"capacity @ {self.lsb_var.get()} LSB: {cap:,} bytes"
        )
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
            self._set_payload_text("")
            self.start_location_var.set("-")

    def _refresh_cover_capacity(self):
        if self.cover_path is None or self.active_kind is None:
            return
        try:
            if self.active_kind == "image":
                self._populate_image_panel("cover", self.cover_path)
            else:
                self._populate_audio_panel("cover", self.cover_path)
        except (tk.TclError, ValueError):
            pass  # spinbox mid-edit (e.g. briefly empty) - ignore, next keystroke will settle it

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

        payload_fields = {"meta": {"course": "INF2005", "team": "P1-6"}}
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
        self._set_payload_text(self._describe_extraction(verdict, extracted))
        self.status_var.set(f"Verified {path.name}: {verdict.name}")

    def _describe_extraction(self, verdict: Verdict, extracted) -> str:
        if extracted is not None:
            match = "yes" if extracted.cover_hash_matches else "NO - the carrier was altered after signing"
            return (
                f"Cover hash embedded at signing:\n{extracted.embedded_cover_hash or '(missing)'}\n\n"
                f"Cover hash recomputed now:\n{extracted.recomputed_cover_hash}\n\n"
                f"Match: {match}\n\n"
                f"Extracted payload:\n{json.dumps(extracted.payload, indent=2, sort_keys=True)}"
            )
        if verdict == Verdict.SIGNATURE_INVALID:
            return (
                "Nothing extracted is shown: the signature did not verify against the trusted key, "
                "so the payload and its cover hash cannot be trusted."
            )
        return "(no verified payload)"

    def _set_payload_text(self, text: str):
        self.payload_text.config(state=tk.NORMAL)
        self.payload_text.delete("1.0", tk.END)
        self.payload_text.insert(tk.END, text)
        self.payload_text.config(state=tk.DISABLED)

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
