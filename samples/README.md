# Sample fixtures

Built by `generate_samples.py` (run: `python samples/generate_samples.py` from
the repo root). All "authentic" samples below use:

- **Passphrase:** `INF2005-P1-6-demo`
- **LSB depth:** 2
- **Signed by:** `keys/demo_a_priv.pem`
- **Message:** Learning Outcome 1, verbatim: "Explain how steganography can be
  used to embed hidden verification data in image and audio cover objects."

Type that passphrase into the GUI's Passphrase field to reproduce `AUTHENTIC`
on the two positive samples.

Every stego fixture carries that message, including the negative cases. The
GUI only displays a recovered message when the signature verifies, so a
negative case can hold the message without the tool revealing it - the
"Message shown" column says which.

| File | Verdict when verified with the passphrase above | Message shown in the GUI? | Notes |
|---|---|---|---|
| `cover.png` | n/a | n/a | Plain 600x600 cover, never embedded into. |
| `cover.wav` | n/a | n/a | Plain 6s/44.1kHz/16-bit mono cover, never embedded into. |
| `stego_image_authentic.png` | `AUTHENTIC` | Yes | Positive case, image. |
| `stego_audio_authentic.wav` | `AUTHENTIC` | Yes | Positive case, audio. |
| `stego_image_tampered.png` | `TAMPERED` | Yes - the signature still verifies; only the cover hash fails | `stego_image_authentic.png` with bit 7 of pixel (0,0)'s red channel flipped after signing - a visible-in-principle edit outside the low 2 bits, caught by the cover hash (§8). |
| `stego_audio_authentic.wav` | `PAYLOAD_MISSING` (with any *other* passphrase) | No - a wrong passphrase can neither find nor decrypt it | Same file as the positive audio case - a wrong passphrase derives a different offset, and the honest, natural result is "no magic marker found anywhere checked," not "found at the wrong place." |
| `stego_image_wrong_key.png` | `SIGNATURE_INVALID` | No - withheld because the signature does not verify | Signed with a throwaway keypair generated only in memory during fixture generation and never committed anywhere - the GUI's verifier only trusts `demo_a`'s public key, so this signature does not validate. |
| `stego_image_wrong_start_location.png` | `WRONG_START_LOCATION` | No - it sits at offset 0, which the tool never reads a payload from | **Doctored, not a normal embed output.** A complete, genuinely signed and encrypted payload is written directly at carrier offset 0 - the one place the real embed flow never writes to (§7's derived offset always lands elsewhere) - and nothing exists at the passphrase-derived offset. This simulates a non-compliant tool that embedded from the first byte, which is exactly the situation `WRONG_START_LOCATION` exists to name, separately from a plain untouched cover (`PAYLOAD_MISSING`). Any passphrase, including the correct one, produces `WRONG_START_LOCATION` for this file. |

`demo_b`'s private key does not exist anywhere in this repo or its history -
see `keys/README.md`. The wrong-key sample above was produced with a
throwaway keypair generated for that single purpose and discarded immediately
after.
