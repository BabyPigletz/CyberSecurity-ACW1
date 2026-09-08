# ACW1 Wire Format & Shared Interfaces

**Version 0.3 — adds `signer_key_id` to the payload JSON (§5) to mitigate signature
stripping/substitution under encrypt-then-sign; extends the §9 SIGNATURE_INVALID row
to check it; fixes §9 rows 2/3, which as originally worded made `PAYLOAD_MISSING`
unreachable (`WRONG_START_LOCATION`'s condition was a superset of it) — row 2 now
requires magic present at offset 0, making the two mutually exclusive. Previous:
RSA-PSS signing, AES-GCM payload encryption, steganalysis as the innovation
component (v0.2).**

Nothing in `core/` should be written until this is agreed. Every decision below is
load-bearing for at least two lanes.

---

## 1. Terminology

**Carrier bytes** — the ordered sequence of bytes in a cover object eligible to hold
payload bits. Defined per cover type in §2. Indexed `0 .. C-1`, where `C` is the
carrier count.

**Prefix** — a fixed 10-byte header, always written at 1 bit per carrier byte, that
tells the decoder how to read everything else.

**Body** — signature, KDF salt, IV and ciphertext, written at `num_lsb` bits per
carrier byte, immediately following the prefix region.

---

## 2. Carrier byte selection

### PNG (image)

- Convert to `RGB` on load. **Alpha excluded** — modifying alpha on partially
  transparent pixels is visible, and some tools normalise it.
- Carrier sequence = raw pixel bytes in row-major order: `R0,G0,B0,R1,G1,B1,...`
- `C = width * height * 3`
- Reject JPEG on the embed path; lossy recompression destroys LSB data. Loading a JPEG
  cover and saving the stego as PNG is fine. Saving stego as JPEG is not.

### WAV / PCM (audio)

- **16-bit PCM: carrier bytes are every second byte only** — the low byte of each
  little-endian sample, i.e. frame-data indices `0, 2, 4, ...`
  Writing to the high byte shifts a sample by up to 256x and is clearly audible. This
  is the most common way this assignment fails its live demo.
- 8-bit PCM: every byte is a carrier.
- `C = num_frames * num_channels` in both cases.
- Read/write via stdlib `wave`. Reject compressed formats.

### Sample media sizing

The large-payload case (the Project Overview paragraph, ~900 chars) produces a body of
roughly 1.2 KB after encryption and signing. With the half-capacity rule in §7, choose:
- image: **at least 512x512** (C = 786,432; ample at 1 LSB)
- audio: **at least 5 seconds, 16-bit, 44.1 kHz** (C >= 220,500)

Verify the large payload fits at `num_lsb = 1`. A demo that only works at 4 LSBs
because the cover is undersized looks weak.

---

## 3. Bit packing convention

Fixed for both codecs, no per-call variation:

- Data bytes are consumed **MSB-first** (bit 7 before bit 0).
- Within a carrier byte, bits fill from **LSB upward**: bit 0 first, then bit 1, up to
  `num_lsb` bits.
- Carrier bytes are consumed in ascending index order from the start position.

`capacity_bytes(C, num_lsb) = (C * num_lsb) // 8`

---

## 4. Prefix layout (10 bytes, always written at 1 LSB)

| Offset | Size | Field      | Notes                                         |
|--------|------|------------|-----------------------------------------------|
| 0      | 4    | `magic`    | ASCII `ACW1`. Presence check for §9 verdicts.  |
| 4      | 1    | `version`  | `0x02`                                        |
| 5      | 1    | `num_lsb`  | 1-8, applies to the body only                 |
| 6      | 4    | `body_len` | uint32 big-endian, byte length of the body    |

Occupies carrier bytes `start .. start+79` (10 bytes x 8 bits, 1 bit per carrier byte).

**Why the prefix is always 1 LSB:** the decoder cannot know `num_lsb` until it reads
it, so the field carrying it must be readable at a fixed, known bit depth. This
two-stage read is what makes a selectable 1-8 LSB setting possible at all.

**Why `magic` is first:** it is the only thing distinguishing *"no payload here"* from
*"reading garbage because the offset is wrong."* Those are separate verdicts.

---

## 5. Body layout

Written at `num_lsb` bits per carrier byte, starting at carrier index `start + 80`.

| Offset       | Size        | Field        |
|--------------|-------------|--------------|
| 0            | 2           | `sig_len`    | uint16 BE; 256 for a 2048-bit key |
| 2            | `sig_len`   | `signature`  | RSA-PSS over `salt \|\| iv \|\| ciphertext` |
| 2+`sig_len`  | 16          | `salt`       | PBKDF2 salt, random per embed |
| 18+`sig_len` | 12          | `iv`         | AES-GCM nonce, random per embed |
| 30+`sig_len` | rest        | `ciphertext` | AES-256-GCM output, 16-byte tag appended |

`sig_len` is present so the RSA key size is not baked into the format.

Plaintext before encryption is UTF-8 JSON, compact separators, **sorted keys**:

```json
{
  "cover_hash": "<hex sha256, see §8>",
  "media_id": "<uuid4>",
  "meta": {"course": "INF2005", "team": "P?-?"},
  "nonce": "<hex, 16 random bytes>",
  "signer_key_id": "<hex, see below>",
  "timestamp": "<ISO 8601 UTC>"
}
```

> **Sign and verify the exact embedded bytes.** Never re-serialise the JSON before
> verifying — key order or whitespace can shift and the signature fails for the wrong
> reason. Extract bytes, verify, decrypt, *then* parse.

**`signer_key_id`.** 16 hex chars: `sha256(DER(SubjectPublicKeyInfo(public_key)))[:8].hex()`.
Computed once when a keypair is loaded, embedded here as a claim of *who signed this
payload*, and checked against the id of whichever key actually validated the RSA-PSS
signature (§9 row 5).

Why this matters under encrypt-then-sign: the signature covers `salt || iv ||
ciphertext`, not this JSON. An attacker who holds a second key the verifier also
trusts (e.g. in a multi-signer keyring) can strip the original signature and
re-sign the same ciphertext with their own key — RSA-PSS verification then
succeeds legitimately, just under the wrong key. Because `signer_key_id` sits
inside the AES-GCM ciphertext, an attacker cannot edit it without either
possessing `aes_key` (they don't) or breaking the GCM tag (caught by row 6
regardless). So a stripped-and-resigned payload verifies under the substitute
key but decrypts to a claim naming the *original* signer — a mismatch only
`signer_key_id` can surface. Under the assignment's default single-trusted-key
verification (one expected public key per session) this adds defence in depth
rather than changing behaviour; it becomes load-bearing the moment the trust
model grows to more than one accepted signer, which the wrong-key demo case
does not require.

---

## 6. Cryptographic parameters

**Key derivation (one passphrase, two keys).**

```python
salt      = os.urandom(16)                     # stored in the body
master    = PBKDF2HMAC(SHA256, length=64, salt=salt, iterations=200_000)
                .derive(passphrase.encode("utf-8"))
aes_key   = HKDF(SHA256, 32, salt=None, info=b"ACW1-aes").derive(master)
hmac_key  = HKDF(SHA256, 32, salt=None, info=b"ACW1-offset").derive(master)
```

Two distinct keys from one passphrase. Reusing the same bytes for encryption and for
the offset HMAC is a cross-purpose key reuse smell and hard to defend in a viva.
PBKDF2 rather than a bare SHA-256 because a human passphrase is low-entropy — the
iteration count is the whole point.

> **Note the ordering problem:** the salt lives in the body, but `hmac_key` is needed
> to find the body. Resolve it by deriving `hmac_key` from a **fixed salt constant**
> (`b"ACW1-offset-salt"`) rather than the random per-embed salt, and using the random
> salt only for `aes_key`. Confirm this in review — it is easy to get backwards and
> produces a decoder that can never locate its own payload.

**Encryption.** AES-256-GCM. The 16-byte GCM tag gives an integrity check independent
of the RSA signature — worth naming during the demo.

**Signing.** RSA-2048, **PSS padding**, SHA-256, MGF1. PSS over PKCS#1 v1.5 because it
is the current recommendation and has a security proof; be ready to say that.

**Encrypt-then-sign.** Sign the ciphertext, not the plaintext. The verifier checks the
signature before decrypting, keeping `SIGNATURE_INVALID` and `TAMPERED` cleanly
separated.

**Keys.** Two demo keypairs committed to `keys/` (`demo_a`, `demo_b`), clearly labelled
demo-only — the brief permits this. `demo_b` exists solely to produce the wrong-key
negative case. Add a "generate new keypair" button; committed keys are what let the
marker reproduce the demo (FR12).

---

## 7. Start-location derivation

Derived, never stored. The decoder recomputes it from the passphrase; nothing in the
file reveals it.

```python
cover_id = f"{kind}:{...}"                      # stego-derivable, see below
digest   = hmac_sha256(hmac_key, cover_id.encode("utf-8"))
start    = int.from_bytes(digest, "big") % (C // 2)
```

`cover_id` may only use properties that embedding does not change:
- image: `f"png:{width}x{height}x3"`
- audio: `f"wav:{sample_width}:{num_channels}:{num_frames}"`

**Why `% (C // 2)`:** the offset must be computable before the prefix is read, so it
cannot depend on `body_len` or `num_lsb`. Reducing into the first half of the carrier
space guarantees room for the prefix plus a body up to roughly half capacity. Cost:
effective capacity halved. State this as a known limitation.

The encoder must still assert
`start + 80 + ceil(body_len*8 / num_lsb) <= C` and raise a capacity error before
writing anything.

**Security framing (criterion 1).** The algorithm is public; only the passphrase is
secret. An attacker who knows the scheme but not the passphrase can still scan all
`C/2` candidate offsets cheaply — so the start location provides *obscurity*, not
confidentiality. Confidentiality comes from AES-GCM; authenticity from RSA-PSS. What
the derived offset buys is a clean failure mode: wrong passphrase, wrong offset, magic
check fails, `WRONG_START_LOCATION`. Say this plainly rather than overclaiming.

---

## 8. Cover hash — the embed-invariant representation

Hashing the cover file and embedding that hash into the same file is self-defeating:
embedding changes the bytes you hashed. The hash must cover a representation identical
before and after embedding.

**Rule: zero the low `num_lsb` bits of *every* carrier byte, then SHA-256.**

```python
def canonical_hash(carrier: bytes, num_lsb: int) -> bytes:
    mask = (0xFF << num_lsb) & 0xFF
    return sha256(bytes(b & mask for b in carrier)).digest()
```

Mask **all** carrier bytes, not only those holding payload. Masking only the used range
would require the verifier to know the payload length and offset in order to reproduce
the hash — circular. Masking everything makes the hash independent of how much was
embedded and where.

Consequence: tampering confined to the masked-off low bits is invisible to this hash.
A genuine limitation; put it in the write-up (criterion 7).

---

## 9. Verdict decision order

One pure function, called by both codecs. First match wins.

| # | Condition                                         | Verdict                |
|---|---------------------------------------------------|------------------------|
| 1 | File unreadable / unsupported format / `C == 0`    | `CANNOT_VERIFY`        |
| 2 | Magic absent at derived offset, present at offset 0 | `WRONG_START_LOCATION` |
| 3 | Magic absent at both offset 0 and derived offset, file otherwise parses | `PAYLOAD_MISSING` |
| 4 | Unknown `version`, or `body_len` exceeds remaining capacity | `CANNOT_VERIFY` |
| 5 | RSA-PSS verification fails against every trusted key, OR succeeds under a key whose id does not match the decrypted payload's `signer_key_id` (§5) | `SIGNATURE_INVALID` |
| 6 | AES-GCM tag check fails                            | `TAMPERED`             |
| 7 | `payload.cover_hash != canonical_hash(...)`        | `TAMPERED`             |
| 8 | All checks pass                                    | `AUTHENTIC`            |

Rows 5-7 must stay distinct and in this order. A failed signature means *this payload
did not come from the holder of the private key*. A failed GCM tag means *the ciphertext
was altered*. A hash mismatch means *the payload is authentic but the carrier changed
since signing*. Articulating those three apart is worth marks under criterion 4.

**Note on evaluation order.** Row 5's second clause (`signer_key_id` mismatch) can only
be known after decryption (row 6) and JSON parsing succeed — later in execution than
row 5's position in this table. This table describes *precedence*, not the order checks
run in: gather all evidence first (magic presence at both offsets, version, body_len,
which key if any validated the signature, GCM tag result, decrypted `signer_key_id`,
`cover_hash`), then apply this table top-to-bottom. If both a signer-id mismatch and a
`cover_hash` mismatch are true simultaneously, `SIGNATURE_INVALID` wins.

---

## 10. Shared interface — `core/bitstream.py`

Owned by the payload/crypto lane. Frozen after Phase 0; both codecs consume it.

```python
def capacity_bytes(carrier_len: int, num_lsb: int) -> int: ...

def write_bits(carrier: bytearray, start: int, data: bytes, num_lsb: int) -> None:
    """Write data into carrier[start:] at num_lsb bits per byte. Mutates in place.
    Raises CapacityError if it will not fit."""

def read_bits(carrier: bytearray, start: int, n_bytes: int, num_lsb: int) -> bytes:
    """Read n_bytes from carrier[start:] at num_lsb bits per byte."""
```

Each codec produces a `bytearray` of carrier bytes per §2 and writes it back to file.
`bitstream` knows nothing about images or audio.

---

## 11. Innovation: steganalysis module

Chosen over scattered embedding, so §3's ascending carrier order stands unchanged.

`core/steganalysis.py` — chi-square attack and/or sample-pair analysis run against a
candidate stego object, reporting a likelihood that a hidden payload is present.
Demonstrate it flagging your own 8-LSB output while missing your 1-LSB output.

This pays into three criteria: innovation (4), limitations (2), and individual viva
answers (5). Owned by whichever lane finishes first, or split: image-side chi-square
and audio-side sample-pair.

---

## 12. Repo scaffolding to add with this commit

```
docs/format.md          this file
keys/demo_a_{priv,pub}.pem
keys/demo_b_pub.pem     wrong-key negative case
samples/                cover, stego and tampered image + audio
tests/
core/bitstream.py       stubs only at Phase 0
core/steganalysis.py
```

---

## 13. Phase 0 exit criteria

Done when this file is committed, `bitstream.py`'s three signatures exist as stubs on
`main`, and each person knows which files they own. Only then do lanes split.

Lane assignment, with demo cases mapped to owners:

| Lane | Files | Demo cases |
|------|-------|-----------|
| A — image | `core/image_stego.py`, image GUI panel, image tests | positive image verify; tampered pixel -> `TAMPERED` |
| B — audio | `core/audio_stego.py`, audio GUI panel + playback, audio tests | positive audio verify; wrong passphrase -> `WRONG_START_LOCATION` |
| C — core | `bitstream.py`, `payload.py`, crypto, verdict logic, GUI shell | wrong key -> `SIGNATURE_INVALID`; oversized payload rejected pre-embed |