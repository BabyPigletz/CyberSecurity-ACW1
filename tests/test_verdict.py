from core.verdict import Evidence, Verdict, decide


def test_unreadable_is_cannot_verify():
    assert decide(Evidence(readable=False)) == Verdict.CANNOT_VERIFY


def test_wrong_start_location_requires_magic_at_zero():
    e = Evidence(magic_at_derived=False, magic_at_zero=True)
    assert decide(e) == Verdict.WRONG_START_LOCATION


def test_payload_missing_when_absent_at_both():
    e = Evidence(magic_at_derived=False, magic_at_zero=False)
    assert decide(e) == Verdict.PAYLOAD_MISSING


def test_rows_2_3_are_mutually_exclusive_by_construction():
    # There is no Evidence value that satisfies both conditions - this is the
    # bug the docs/format.md v0.3 fix closed. Sweep the boolean pair to prove it.
    seen = set()
    for derived in (True, False):
        for zero in (True, False):
            if derived:
                continue  # rows 2/3 only apply when magic is absent at derived
            e = Evidence(magic_at_derived=derived, magic_at_zero=zero)
            seen.add(decide(e))
    assert seen == {Verdict.WRONG_START_LOCATION, Verdict.PAYLOAD_MISSING}


def test_unknown_version_is_cannot_verify():
    e = Evidence(magic_at_derived=True, version_known=False)
    assert decide(e) == Verdict.CANNOT_VERIFY


def test_body_len_overflow_is_cannot_verify():
    e = Evidence(magic_at_derived=True, body_len_fits=False)
    assert decide(e) == Verdict.CANNOT_VERIFY


def test_no_verifying_key_is_signature_invalid():
    e = Evidence(magic_at_derived=True, verified_key_id=None)
    assert decide(e) == Verdict.SIGNATURE_INVALID


def test_signer_key_id_mismatch_is_signature_invalid():
    e = Evidence(
        magic_at_derived=True,
        verified_key_id="aaaaaaaaaaaaaaaa",
        claimed_signer_key_id="bbbbbbbbbbbbbbbb",
        gcm_tag_ok=True,
        cover_hash_matches=True,
    )
    assert decide(e) == Verdict.SIGNATURE_INVALID


def test_signer_key_id_match_proceeds_to_authentic():
    e = Evidence(
        magic_at_derived=True,
        verified_key_id="aaaaaaaaaaaaaaaa",
        claimed_signer_key_id="aaaaaaaaaaaaaaaa",
        gcm_tag_ok=True,
        cover_hash_matches=True,
    )
    assert decide(e) == Verdict.AUTHENTIC


def test_gcm_failure_with_valid_signature_is_tampered_not_signature_invalid():
    # Regression guard: a genuinely valid signature plus a broken GCM tag means
    # the ciphertext was altered after signing - never SIGNATURE_INVALID, even
    # though claimed_signer_key_id is unavailable (decryption never got that far).
    e = Evidence(
        magic_at_derived=True,
        verified_key_id="aaaaaaaaaaaaaaaa",
        claimed_signer_key_id=None,
        gcm_tag_ok=False,
    )
    assert decide(e) == Verdict.TAMPERED


def test_cover_hash_mismatch_is_tampered():
    e = Evidence(
        magic_at_derived=True,
        verified_key_id="aaaaaaaaaaaaaaaa",
        claimed_signer_key_id="aaaaaaaaaaaaaaaa",
        gcm_tag_ok=True,
        cover_hash_matches=False,
    )
    assert decide(e) == Verdict.TAMPERED


def test_all_clean_is_authentic():
    e = Evidence(
        magic_at_derived=True,
        verified_key_id="aaaaaaaaaaaaaaaa",
        claimed_signer_key_id="aaaaaaaaaaaaaaaa",
        gcm_tag_ok=True,
        cover_hash_matches=True,
    )
    assert decide(e) == Verdict.AUTHENTIC


def test_signature_invalid_takes_precedence_over_hash_mismatch():
    # Both a signer-id mismatch and a cover-hash mismatch true at once:
    # SIGNATURE_INVALID must win per §9's precedence order.
    e = Evidence(
        magic_at_derived=True,
        verified_key_id="aaaaaaaaaaaaaaaa",
        claimed_signer_key_id="bbbbbbbbbbbbbbbb",
        gcm_tag_ok=True,
        cover_hash_matches=False,
    )
    assert decide(e) == Verdict.SIGNATURE_INVALID
