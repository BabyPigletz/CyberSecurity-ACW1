# Sample fixtures

Built by `generate_samples.py` (run: `python samples/generate_samples.py` from
the repo root). All "authentic" samples below use:

- **Passphrase:** `INF2005-P1-6-demo`
- **LSB depth:** 2
- **Signed by:** `keys/demo_a_priv.pem`

Type that passphrase into the GUI's Passphrase field to reproduce `AUTHENTIC`
on the two positive samples.

| File | Verdict when verified with the passphrase above | Notes |
|---|---|---|
| `cover.png` | n/a | Plain 600x600 cover, never embedded into. |
| `cover.wav` | n/a | Plain 6s/44.1kHz/16-bit mono cover, never embedded into. |
| `stego_image_authentic.png` | `AUTHENTIC` | Positive case, image. |
| `stego_audio_authentic.wav` | `AUTHENTIC` | Positive case, audio. |
| `stego_image_tampered.png` | `TAMPERED` | `stego_image_authentic.png` with bit 7 of pixel (0,0)'s red channel flipped after signing - a visible-in-principle edit outside the low 2 bits, caught by the cover hash (§8). |
| `stego_audio_authentic.wav` | `PAYLOAD_MISSING` (with any *other* passphrase) | Same file as the positive audio case - a wrong passphrase derives a different offset, and the honest, natural result is "no magic marker found anywhere checked," not "found at the wrong place." See the report for why this is `PAYLOAD_MISSING` rather than `WRONG_START_LOCATION`. |
| `stego_image_wrong_key.png` | `SIGNATURE_INVALID` | Signed with a throwaway keypair generated only in memory during fixture generation and never committed anywhere - the GUI's verifier only trusts `demo_a`'s public key, so this signature does not validate. |
| `stego_image_wrong_start_location.png` | `WRONG_START_LOCATION` | **Doctored, not a normal embed output.** A well-formed 10-byte prefix (magic + version + num_lsb + an arbitrary, never-read body_len) is planted directly at carrier offset 0 - the one place the real embed flow never writes to (§7's derived offset always lands elsewhere). No real payload exists at the passphrase-derived offset. This simulates "a stray magic marker happens to be sitting at offset 0" (e.g. a different, non-compliant tool's output), which is exactly the situation `WRONG_START_LOCATION` exists to name, separately from a plain untouched cover (`PAYLOAD_MISSING`). Any passphrase (including the correct one above) produces `WRONG_START_LOCATION` for this file, since no real body was ever embedded in it. |

`demo_b`'s private key does not exist anywhere in this repo or its history -
see `keys/README.md`. The wrong-key sample above was produced with a
throwaway keypair generated for that single purpose and discarded immediately
after.
