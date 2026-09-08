import pytest

from core.errors import CapacityError
from core.location import cover_id_for_audio, cover_id_for_image, derive_start


def test_deterministic():
    a = derive_start("png:512x512x3", "hunter2", 786432)
    b = derive_start("png:512x512x3", "hunter2", 786432)
    assert a == b


def test_different_passphrase_gives_different_offset():
    a = derive_start("png:512x512x3", "hunter2", 786432)
    b = derive_start("png:512x512x3", "different", 786432)
    assert a != b


def test_different_cover_id_gives_different_offset():
    a = derive_start("png:512x512x3", "hunter2", 786432)
    b = derive_start("wav:2:1:220500", "hunter2", 786432)
    assert a != b


def test_offset_within_first_half():
    carrier_len = 786432
    start = derive_start("png:512x512x3", "hunter2", carrier_len)
    assert 0 <= start < carrier_len // 2


def test_degenerate_carrier_raises_capacity_error_not_zero_division():
    with pytest.raises(CapacityError):
        derive_start("png:1x1x3", "hunter2", 1)
    with pytest.raises(CapacityError):
        derive_start("png:1x1x3", "hunter2", 0)


def test_cover_id_formats():
    assert cover_id_for_image(512, 512) == "png:512x512x3"
    assert cover_id_for_audio(2, 1, 220500) == "wav:2:1:220500"
