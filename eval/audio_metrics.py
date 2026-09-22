"""Quality measurements for cover/stego PCM WAV pairs."""

from dataclasses import dataclass
import math
import wave
from pathlib import Path


@dataclass(frozen=True)
class AudioQualityMetrics:
    sample_count: int
    changed_samples: int
    mean_absolute_error: float
    maximum_absolute_error: int
    signal_to_noise_db: float

    @property
    def changed_percent(self) -> float:
        return (self.changed_samples / self.sample_count * 100.0) if self.sample_count else 0.0


def _read_samples(path: Path) -> tuple[tuple[int, ...], wave._wave_params]:
    with wave.open(str(path), "rb") as reader:
        params = reader.getparams()
        raw = reader.readframes(reader.getnframes())

    if params.comptype != "NONE":
        raise ValueError(f"compressed WAV ({params.comptype}) is not supported")
    if params.sampwidth not in (1, 2):
        raise ValueError(f"unsupported sample width: {params.sampwidth * 8}-bit")

    if params.sampwidth == 2:
        samples = tuple(
            int.from_bytes(raw[index:index + 2], "little", signed=True)
            for index in range(0, len(raw), 2)
        )
    else:
        samples = tuple(raw)
    return samples, params


def compare(cover_path: Path, stego_path: Path) -> AudioQualityMetrics:
    """Compare decoded PCM samples and report embedding distortion."""
    cover, cover_params = _read_samples(cover_path)
    stego, stego_params = _read_samples(stego_path)
    if cover_params != stego_params:
        raise ValueError("cover and stego WAV formats do not match")
    if len(cover) != len(stego):
        raise ValueError("cover and stego WAV sample counts do not match")

    differences = [stego_sample - cover_sample for cover_sample, stego_sample in zip(cover, stego)]
    absolute = [abs(difference) for difference in differences]
    signal_power = sum(sample * sample for sample in cover) / len(cover) if cover else 0.0
    noise_power = sum(difference * difference for difference in differences) / len(differences) if differences else 0.0
    if noise_power == 0.0:
        snr = math.inf
    elif signal_power == 0.0:
        snr = 0.0
    else:
        snr = 10.0 * math.log10(signal_power / noise_power)

    return AudioQualityMetrics(
        sample_count=len(differences),
        changed_samples=sum(value != 0 for value in differences),
        mean_absolute_error=sum(absolute) / len(absolute) if absolute else 0.0,
        maximum_absolute_error=max(absolute, default=0),
        signal_to_noise_db=snr,
    )
