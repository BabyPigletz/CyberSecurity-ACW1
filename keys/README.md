# Demo keys — not for real use

`demo_a_priv.pem` / `demo_a_pub.pem` and `demo_b_pub.pem` are RSA-2048 keypairs
generated solely for this assignment's demo cases (see `docs/format.md` §6, §13).

- `demo_a` is the "legitimate signer" used for the positive and tampered-carrier
  demo cases.
- `demo_b_pub.pem` exists only so a verifier can be shown rejecting a payload
  signed by a different key (`SIGNATURE_INVALID`). `demo_b`'s private half is
  deliberately **not** committed — it is generated locally, used once to sign
  the wrong-key sample committed under `samples/`, and discarded (`.gitignore`
  only allows `demo_a_priv.pem`, `demo_a_pub.pem`, and `demo_b_pub.pem` through
  its blanket `*.pem` exclusion).

These are throwaway keys with no connection to any real identity. Never reuse
them, and never commit a real private key here.
