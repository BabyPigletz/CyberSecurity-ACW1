"""Chi-square steganalysis (docs/format.md §11) - Westfeld & Pfitzmann's
Pairs-of-Values (PoV) attack.

A statistical test for LSB-replacement embedding, operating on any flat byte
sequence. Knows nothing about images, audio, or this project's own payload
format - a real attacker analysing a suspect file wouldn't have that either,
and the point of this module is to demonstrate the detector's-eye view.
"""

import math
from typing import List, Tuple


def _regularized_lower_incomplete_gamma(a: float, x: float) -> float:
    """P(a, x), via series expansion (x < a+1) or a continued fraction
    (x >= a+1) - the standard numerical-recipes split. Used to turn a
    chi-square statistic into a p-value without adding a scipy dependency
    for one function.
    """
    if x < 0 or a <= 0:
        raise ValueError("a must be > 0 and x must be >= 0")
    if x == 0:
        return 0.0

    if x < a + 1:
        term = 1.0 / a
        total = term
        n = a
        for _ in range(400):
            n += 1
            term *= x / n
            total += term
            if abs(term) < abs(total) * 1e-14:
                break
        return total * math.exp(-x + a * math.log(x) - math.lgamma(a))

    tiny = 1e-300
    b = x + 1 - a
    c = 1 / tiny
    d = 1 / b
    h = d
    for i in range(1, 400):
        an = -i * (i - a)
        b += 2
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1 / d
        delta = d * c
        h *= delta
        if abs(delta - 1) < 1e-14:
            break
    q = math.exp(-x + a * math.log(x) - math.lgamma(a)) * h
    return 1 - q


def chi_square_pvalue(window: bytes) -> float:
    """p-value that window's byte-value pair frequencies (2k, 2k+1) are
    consistent with random LSBs. Close to 1 => this region's LSBs look
    randomized (consistent with LSB-replacement embedding); close to 0 =>
    pair frequencies look like an untouched, structured region.
    """
    hist = [0] * 256
    for b in window:
        hist[b] += 1

    chi_sq = 0.0
    dof = 0
    for k in range(128):
        h_even, h_odd = hist[2 * k], hist[2 * k + 1]
        expected = (h_even + h_odd) / 2.0
        if expected < 4:
            continue  # too sparse for a meaningful term - standard practice
        chi_sq += (h_even - expected) ** 2 / expected
        dof += 1

    if dof < 2:
        return 0.0
    k_dof = dof - 1
    p_value = 1.0 - _regularized_lower_incomplete_gamma(k_dof / 2.0, chi_sq / 2.0)
    return max(0.0, min(1.0, p_value))


def scan(carrier: bytes, window: int = 512, step: int = 256) -> List[Tuple[int, float]]:
    """Sliding-window chi-square p-values across carrier. A likely-embedded
    region shows p_value spiking toward 1 within it.
    """
    results = []
    for start in range(0, max(len(carrier) - window, 0) + 1, step):
        chunk = carrier[start:start + window]
        results.append((start, chi_square_pvalue(chunk)))
    return results


def flagged(carrier: bytes, window: int = 512, step: int = 256, threshold: float = 0.9) -> bool:
    """True if any window's p-value reaches threshold - a pass/fail summary
    of scan() for a quick demo assertion or a GUI indicator.
    """
    return any(p >= threshold for _, p in scan(carrier, window, step))
