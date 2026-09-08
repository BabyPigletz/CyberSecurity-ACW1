"""
Tkinter GUI Skeleton for Steganographic Image and Audio Integrity

Implemented:
- Load and preview a cover image
- Basic file info panel (dimensions, mode, size, rough 1-LSB capacity)
- LSB-bit-count selector (1-8) - valu only
- Placeholder embed / Extract buttons and start-locations section


NOT IMPLEMENTED
- Actual LSB embed/extract logic
- Audio cover object support
- Payload build / hash / sign / verify
- Start-location selection + recovery logic
- Verdict display (Authentic/tampered etc.)

"""

import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path

from PIL import Image, ImageTk

class ACW1(tk.Tk):
    ## Main application Window
    THUMB_MAX_SIZE = (400,400)

    def __init__(self):
        super().__init__()
        self.title("ACW1 (Steganography) - Lab P1 Group 6")
        self.geometry("900x600")
        self.minsize(700,500)

        ## App State
        self.image_path: Path | None = None
        self.pil_image: Image.Image | None = None
        self.tk_image: ImageTk.PhotoImage | None = None

        self._build_menu()
        self._build_layout()

    ## UI Construction
    def _build_menu(self):
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff = 0)
        file_menu.add_command(label = "Open Image...", command = self.load_image)
        file_menu.add_separator()
        file_menu.add_command(label = "Exit", command = self.quit)
        menubar.add_cascade(label = "File", menu = file_menu)

        self.config(menu = menubar)

    def _build_layout(self):
        # Left: Image Preview
        left_frame = tk.Frame(self, bd = 1, relief = tk.SUNKEN)
        left_frame.pack(side = tk.LEFT, fill = tk.BOTH, expand = True, padx = 8, pady = 8)

        tk.Label(left_frame, text = "Cover Image Preview", font = ("Segoe UI", 11, "bold")).pack(pady = (6,0))

        self.image_label = tk.Label(left_frame, text = "No image loaded", bg = "#eeeeee")
        self.image_label.pack(fill = tk.BOTH, expand = True, padx = 10, pady = 10)

        tk.Button(left_frame, text = "Load Image...", command = self.load_image).pack(pady = (0, 10))

        # Right: Info + controls (Future)
        right_frame = tk.Frame(self, width = 280)
        right_frame.pack(side = tk.RIGHT, fill = tk.Y, padx = 8, pady = 8)
        right_frame.pack_propagate(False)

        tk.Label(right_frame, text = "Image Info", font = ("Sergoe UI", 11, "bold")).pack(anchor = "w", pady = (6, 4))
        self.info_text = tk.Text(right_frame, height = 12, width = 32, state = tk.DISABLED, wrap = tk.WORD)
        self.info_text.pack(fill = tk.X)

        tk.Label(right_frame, text = "LSB Bits to Use (1-8)", font = ("Sergoe UI", 10, "bold")).pack(anchor = "w", pady = (16, 2))
        self.lsb_var = tk.IntVar(value = 1)
        tk.Spinbox(right_frame, from_= 1, to = 8, textvariable = self.lsb_var, width = 5).pack(anchor = "w")

        tk.Label(right_frame, text = "Start Location", font = ("Sergoe UI", 10, "bold")).pack(anchor = "w", pady = (16, 2))
        tk.Label(right_frame, text = "Design TODO Later", fg = "Gray").pack(anchor = "w")

        tk.Label(right_frame, text = "Actions", font = ("Sergoe UI", 10, "bold")).pack(anchor = "w", pady = (20, 4))
        tk.Button(right_frame, text = "Embed Payload...", state = tk.DISABLED).pack(fill = tk.X, pady = 2)
        tk.Button(right_frame, text = "Extract Payload...", state = tk.DISABLED).pack(fill = tk.X, pady = 2)

        # Status Bar
        self.status_var = tk.StringVar(value = "Ready.")
        tk.Label(self, textvariable = self.status_var, bd = 1, relief = tk.SUNKEN, anchor = "w").pack(side = tk.BOTTOM, fill = tk.X)

    ## Actions
    def load_image(self):
        path = filedialog.askopenfilename(
            title = "Select Cover Image",
            filetypes = [("Image Files", "*.png *.bmp *.jpg *.jpeg"), ("All files", "*.*")],
        )

        if not path:
            return

        try:
            img = Image.open(path)
            img.load()
        except Exception as exc:
            messagebox.showerror("Error loading image", f"Could not open image: \n{exc}")
            return

        self.image_path = Path(path)
        self.pil_image = img
        self._show_preview(img)
        self._update_info(img)
        self.status_var.set(f"Loaded: {self.image_path.name}")

    def _show_preview(self, img: Image.Image):
        preview = img.copy()
        preview.thumbnail(self.THUMB_MAX_SIZE)
        self.tk_image = ImageTk.PhotoImage(preview)
        self.image_label.config(image = self.tk_image, text = "")

    def _update_info(self, img: Image.Image):
        width, height = img.size
        mode = img.mode
        channels = len(mode) if mode != "P" else 1
        file_size = self.image_path.stat().st_size if self.image_path else 0

        ## Rough capacity estimate at 1 LSB bit per pixel
        capacity_1bit_bytes = (width * height * channels) // 8

        info = (
            f"File: {self.image_path.name}\n"
            f"Path: {self.image_path}\n"
            f"Dimensions: {width} x {height}\n"
            f"Mode: {mode} ({channels} channel(s))\n"
            f"File Size: {file_size:,} bytes\n"
            f"Est. Capacity at 1 LSB {capacity_1bit_bytes:,}\n"
            f"(capacity scales -linearly with LSB bits used)"
        )

        self.info_text.config(state=tk.NORMAL)
        self.info_text.delete("1.0", tk.END)
        self.info_text.insert(tk.END, info)
        self.info_text.config(state = tk.DISABLED)