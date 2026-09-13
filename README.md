# CyberSecurity-ACW1 — Steganographic Integrity Tool

INF2005 assignment (Lab P1, Group 6). A Tkinter GUI that embeds a signed,
encrypted verification payload into a PNG or WAV cover object using
LSB-replacement steganography (1–8 bits, selectable), then extracts and
verifies it, reporting one of six verdicts.

Byte-level format, cryptographic parameters, and module interfaces are
specified in [`docs/format.md`](docs/format.md) — that document is authoritative;
this README explains the *why*, not the wire layout.

## Setup & run

```
pip install -r requirements.txt
python main.py
```

Demo keypairs live under `keys/` (`demo_a`: full pair; `demo_b`: public key
only, used to produce the wrong-key negative case). Do not treat either as a
real secret — see `docs/format.md` §6.

To run the test suite (95 tests, all against synthetic data or the fixtures
in `samples/` — no real image/audio hardware needed except for actually
*hearing* playback, which the tests don't attempt):

```
pip install -r requirements-dev.txt
pytest
```

`samples/generate_samples.py` rebuilds the fixtures under `samples/` (a cover
PNG/WAV and one sample per verdict) if you ever need to regenerate them;
`samples/README.md` documents the passphrase and expected verdict for each.

The GUI also includes an innovation evaluation framework. **Run Attack
Simulation** creates safe copies of the current stego object with visible-carrier
tampering, hidden-payload corruption, wrong-passphrase, untrusted-key, and
replay/substitution cases. It reports a weighted detection score and, for WAV,
also reports changed samples, mean absolute error, and signal-to-noise ratio.
**Compare Steganalysis** compares matching cover/stego windows at multiple
scales and reports cross-scale agreement. Attack artifacts are written to a
folder selected in the GUI; the original stego object is never changed.

## What it does

Given a cover PNG or WAV and a passphrase, the tool derives a start location
inside the file, encrypts and signs a small JSON payload (media ID, timestamp,
nonce, team metadata, a hash of the cover, and the signer's key id), and writes
it into the low bits of the cover starting at that location. Extraction
reverses the process from the passphrase alone — no side channel carries the
offset, the LSB count, or the key — and produces a verdict rather than a bare
pass/fail.

## Security model

Three independent mechanisms, each protecting something different:

- **AES-256-GCM encryption** protects the payload's *confidentiality* and
  gives a tamper-evident tag over the ciphertext (a `TAMPERED` verdict if the
  ciphertext was altered after signing).
- **RSA-PSS signing** protects *authenticity and origin* — proof the payload
  was produced by the holder of a specific private key (`SIGNATURE_INVALID`
  if not, or if signed but the plaintext's claimed signer doesn't match the
  key that actually verified — see §5's `signer_key_id`).
- **SHA-256 over a masked cover representation** protects the *carrier's*
  integrity independently of the payload (`TAMPERED` if the visible pixels/
  samples changed since signing, even though the payload itself decrypts and
  verifies fine).
- **HKDF key separation** derives independent offset and AES subkeys using
  distinct context labels. A passphrase-derived location key cannot be reused
  as an encryption key, even though both are derived from the same passphrase.

**What none of this protects against:** a leaked or guessed passphrase
(everything downstream — offset, AES key, HMAC key — derives from it, so it
is a single point of failure by design, not oversight); the mere fact that
*something* is hidden in the file (that's a presence/detection problem, which
is what the steganalysis module targets separately, not something encryption
or signing can hide); or destruction of the file outright (there's no
redundancy or error correction — a badly damaged cover just reads as
`CANNOT_VERIFY`).

## Why the start location is derived, not stored

Storing the offset anywhere in the file (a header field, metadata) makes it
findable by anyone who has the file, regardless of whether they have the
passphrase. Instead, the offset is computed as `HMAC-SHA256(hmac_key,
cover_id) mod (C/2)`, where `hmac_key` comes from the passphrase and
`cover_id` from properties embedding never changes (image dimensions; audio
frame/channel/sample-width counts). The decoder recomputes the same value
independently — nothing on disk reveals it.

Be honest about what this buys: the *algorithm* is public (it's in this
repo). An attacker without the passphrase but with the scheme can still scan
every candidate offset in `C/2` cheaply looking for the magic marker — this is
**obscurity, not confidentiality**. Confidentiality is AES-GCM's job;
authenticity is RSA-PSS's job. What the derived offset actually buys is a
clean, explainable failure mode: wrong passphrase → wrong offset → magic
check fails → `WRONG_START_LOCATION`, rather than silent success or a generic
error.

## Why the cover hash is over an LSB-masked representation

Hashing the cover file and then writing that hash into the same file is
self-defeating — embedding changes the bytes you just hashed, so extraction
would never reproduce it. The hash is instead computed after zeroing the low
`num_lsb` bits of *every* carrier byte (not just the ones actually used),
before embedding on the encode side and after extraction on the decode side.
Masking every carrier byte (not only the used range) keeps the hash
independent of payload length and offset — masking only the used range would
require already knowing the length and offset to reproduce the hash, which is
circular.

The honest limitation: tampering confined entirely to the masked-off low bits
is invisible to this hash. That's a real gap, not an edge case we're ignoring
— it's called out in `docs/format.md` §8 and worth stating plainly in the
write-up.

**This gap is much larger for audio than for images.** For 16-bit PCM WAV,
§2 defines the carrier as the *low byte only* of each sample — so the cover
hash never sees the high byte at all, not just its low `num_lsb` bits. The
high byte is the dominant, audible half of the sample: an attacker can
substantially alter the audio's actual sound by rewriting every high byte and
this system reports `AUTHENTIC`, because canonical_hash only ever hashes
`carrier`, and the high bytes were never part of `carrier` to begin with.
This was confirmed empirically, not just reasoned about — see
`tests/test_audio_stego.py`'s `test_KNOWN_GAP_high_byte_tamper_is_invisible_to_cover_hash`.
For images, by contrast, nearly the entire pixel byte range *is* the carrier
(only alpha is excluded), so this gap there really is confined to a handful
of low bits per channel, as originally described above. Closing this for
audio would mean hashing over the full raw sample buffer (masking only the
carrier positions' low bits, leaving high bytes unmasked) rather than just
the extracted carrier array — a real design change with its own tradeoffs,
not applied here; flagged as a limitation rather than fixed.

## Why encrypt-then-sign, and what `signer_key_id` adds

The signature covers the ciphertext, not the plaintext, so a verifier can
reject a forged or corrupted signature *before* spending effort decrypting —
`SIGNATURE_INVALID` and `TAMPERED` stay cleanly separated (§9 explains why
that separation matters for criterion 4).

Encrypt-then-sign has a known weakness: if a verifier is ever willing to trust
more than one public key, an attacker holding a second trusted keypair can
strip the original signature off a captured ciphertext and re-sign it with
their own key — that signature verifies *correctly*, just under the wrong
identity. Embedding `signer_key_id` inside the encrypted plaintext closes
this: the claimed signer travels with content an attacker cannot edit without
either the AES key or breaking the GCM tag, so a verifier can compare "which
key actually validated this" against "which key the payload claims did," and
flag a mismatch as `SIGNATURE_INVALID`. Under this project's default
single-trusted-key verification this is defence in depth rather than
something the required demo depends on; it's what makes the design sound if
extended to multiple signers later.

## The six verdicts

| Verdict | Meaning |
|---|---|
| `AUTHENTIC` | Signature, ciphertext integrity, and cover hash all check out. |
| `TAMPERED` | Payload is genuinely signed, but either the ciphertext or the visible carrier changed since signing. |
| `SIGNATURE_INVALID` | No trusted key validates the signature, or the plaintext's claimed signer doesn't match the key that did. |
| `PAYLOAD_MISSING` | No magic marker found at the derived offset or at offset 0 — this looks like a plain, unmodified cover. |
| `WRONG_START_LOCATION` | Magic marker not found at the derived offset, but present at offset 0 — this stego object doesn't match this passphrase. |
| `CANNOT_VERIFY` | File unreadable, unsupported format, or an internal field (version, declared length) doesn't make sense — verification can't even be attempted. |

Full precedence rules: `docs/format.md` §9.

**A nuance found during implementation:** because the RSA-PSS signature
covers the entire `salt || iv || ciphertext` range, any tamper severe enough
to break the AES-GCM tag also breaks the signature — so `TAMPERED` is only
ever reached in practice via a cover-hash mismatch (editing the visible,
unsigned carrier bytes), not via a broken GCM tag with an otherwise-valid
signature. That combination is correctly implemented and unit-tested in
isolation (`tests/test_verdict.py`), but has no realistic external trigger
given this signing scope — not a bug, just worth knowing before relying on
it as a second, independently-reachable demo path.

## Steganalysis (innovation component)

`core/steganalysis.py` implements Westfeld & Pfitzmann's chi-square
Pairs-of-Values attack — a sliding-window statistical test that flags
regions whose byte-value pairs look artificially randomized, which is what
LSB-replacement produces. Verified against a constructed buffer (a
structured region directly adjacent to genuine random bytes) where the
windowed p-value transitions sharply and exactly at the boundary — see
`tests/test_steganalysis.py`. The multi-scale extension repeats the paired
comparison at 512, 1024, and 2048-byte windows and reports how many scales
agree before presenting a suspicious-region assessment.

`core/attack_simulation.py` also tests replay resistance by transplanting a
valid encrypted payload into a different cover. The embedded cover hash then
fails against the new carrier and produces `TAMPERED`, demonstrating that a
valid signed payload cannot simply be reused with another media object.

The paired analysis extension compares the original cover and stego windows,
requiring both a high stego p-value and a meaningful increase over the cover's
p-value before marking a region suspicious. This is statistical evidence, not
proof of hidden data or tampering. `core/attack_simulation.py` provides the
companion reproducible security test matrix used by the GUI and automated
tests.

**Caveat found while testing this:** `docs/format.md` §11's demo claim
("flags your own 8-LSB output while missing your 1-LSB output") could not be
reliably reproduced against the synthetic cover images generated in this
environment — a clean, regular pattern never triggers the attack regardless
of embedding, and a jittered/noisy synthetic pattern already looks close to
random in its low bits regardless of embedding. Real camera sensor noise
sits between those two extremes, which neither synthetic approach
reproduces. **Test this against a real photograph before the actual demo** —
don't assume the synthetic samples in this repo will show the effect.

## Known limitations

- **Halved effective capacity.** The derived offset lands in the first half of
  the carrier space (§7) so a prefix-plus-body always fits regardless of
  where the offset falls — real usable capacity per cover is roughly half the
  naive `C * num_lsb / 8` figure.
- **LSB fragility.** Any recompression (saving stego output as JPEG) or
  resampling (audio sample-rate conversion) destroys the low bits the payload
  lives in. The tool only supports PNG and uncompressed PCM WAV for exactly
  this reason.
- **Passphrase as single point of failure.** It drives both the encryption
  key and the offset-derivation key. Lose it and the payload is
  unrecoverable, even by whoever embedded it; leak it and both
  confidentiality and the "obscurity" of the start location are gone at once.
