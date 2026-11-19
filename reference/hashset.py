"""Zero-dependency Python 3 reference implementation of the Hashset format.

See SPEC.md for the normative specification.
"""

from __future__ import annotations

import hmac
import re
from collections.abc import Callable, Mapping, Sequence, Set

ALG_RE = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")

Hasher = Callable[[bytes], bytes]


class HashsetError(ValueError):
    """Raised on invalid Hashset syntax or verification failure."""


def _b32_encode_digit(n: int) -> str:
    return chr(ord("a") + n) if n < 26 else chr(ord("2") + (n - 26))


def _b32_decode_char(c: str) -> int:
    o = ord(c)
    if 0x61 <= o <= 0x7A:  # 'a'..'z'
        return o - 0x61
    if 0x32 <= o <= 0x37:  # '2'..'7'
        return 26 + (o - 0x32)
    raise HashsetError(f"invalid base32 character: {c!r}")


def b32_encode(data: bytes) -> str:
    """Canonical unpadded lowercase RFC 4648 §6 Base32 encoder."""
    if not data:
        raise HashsetError("digest must be non-empty")
    out: list[str] = []
    i = 0
    n = len(data)
    while i + 5 <= n:
        b0, b1, b2, b3, b4 = data[i : i + 5]
        out.append(_b32_encode_digit(b0 >> 3))
        out.append(_b32_encode_digit(((b0 & 0x07) << 2) | (b1 >> 6)))
        out.append(_b32_encode_digit((b1 >> 1) & 0x1F))
        out.append(_b32_encode_digit(((b1 & 0x01) << 4) | (b2 >> 4)))
        out.append(_b32_encode_digit(((b2 & 0x0F) << 1) | (b3 >> 7)))
        out.append(_b32_encode_digit((b3 >> 2) & 0x1F))
        out.append(_b32_encode_digit(((b3 & 0x03) << 3) | (b4 >> 5)))
        out.append(_b32_encode_digit(b4 & 0x1F))
        i += 5
    rem = data[i:]
    r = len(rem)
    if r == 1:
        (b0,) = rem
        out.append(_b32_encode_digit(b0 >> 3))
        out.append(_b32_encode_digit((b0 & 0x07) << 2))
    elif r == 2:
        b0, b1 = rem
        out.append(_b32_encode_digit(b0 >> 3))
        out.append(_b32_encode_digit(((b0 & 0x07) << 2) | (b1 >> 6)))
        out.append(_b32_encode_digit((b1 >> 1) & 0x1F))
        out.append(_b32_encode_digit((b1 & 0x01) << 4))
    elif r == 3:
        b0, b1, b2 = rem
        out.append(_b32_encode_digit(b0 >> 3))
        out.append(_b32_encode_digit(((b0 & 0x07) << 2) | (b1 >> 6)))
        out.append(_b32_encode_digit((b1 >> 1) & 0x1F))
        out.append(_b32_encode_digit(((b1 & 0x01) << 4) | (b2 >> 4)))
        out.append(_b32_encode_digit((b2 & 0x0F) << 1))
    elif r == 4:
        b0, b1, b2, b3 = rem
        out.append(_b32_encode_digit(b0 >> 3))
        out.append(_b32_encode_digit(((b0 & 0x07) << 2) | (b1 >> 6)))
        out.append(_b32_encode_digit((b1 >> 1) & 0x1F))
        out.append(_b32_encode_digit(((b1 & 0x01) << 4) | (b2 >> 4)))
        out.append(_b32_encode_digit(((b2 & 0x0F) << 1) | (b3 >> 7)))
        out.append(_b32_encode_digit((b3 >> 2) & 0x1F))
        out.append(_b32_encode_digit((b3 & 0x03) << 3))
    return "".join(out)


def b32_decode(text: str) -> bytes:
    """Strict canonical unpadded lowercase RFC 4648 §6 & §3.5 Base32 decoder."""
    if not text:
        raise HashsetError("empty base32 digest")
    vals = [_b32_decode_char(c) for c in text]
    out = bytearray()
    i = 0
    n = len(vals)
    while i + 8 <= n:
        c0, c1, c2, c3, c4, c5, c6, c7 = vals[i : i + 8]
        out.append((c0 << 3) | (c1 >> 2))
        out.append(((c1 & 0x03) << 6) | (c2 << 1) | (c3 >> 4))
        out.append(((c3 & 0x0F) << 4) | (c4 >> 1))
        out.append(((c4 & 0x01) << 7) | (c5 << 2) | (c6 >> 3))
        out.append(((c6 & 0x07) << 5) | c7)
        i += 8
    rem = vals[i:]
    r = len(rem)
    if r == 0:
        pass
    elif r == 2:
        c0, c1 = rem
        if c1 & 0x03:
            raise HashsetError("non-canonical trailing base32 bits")
        out.append((c0 << 3) | (c1 >> 2))
    elif r == 4:
        c0, c1, c2, c3 = rem
        if c3 & 0x0F:
            raise HashsetError("non-canonical trailing base32 bits")
        out.append((c0 << 3) | (c1 >> 2))
        out.append(((c1 & 0x03) << 6) | (c2 << 1) | (c3 >> 4))
    elif r == 5:
        c0, c1, c2, c3, c4 = rem
        if c4 & 0x01:
            raise HashsetError("non-canonical trailing base32 bits")
        out.append((c0 << 3) | (c1 >> 2))
        out.append(((c1 & 0x03) << 6) | (c2 << 1) | (c3 >> 4))
        out.append(((c3 & 0x0F) << 4) | (c4 >> 1))
    elif r == 7:
        c0, c1, c2, c3, c4, c5, c6 = rem
        if c6 & 0x07:
            raise HashsetError("non-canonical trailing base32 bits")
        out.append((c0 << 3) | (c1 >> 2))
        out.append(((c1 & 0x03) << 6) | (c2 << 1) | (c3 >> 4))
        out.append(((c3 & 0x0F) << 4) | (c4 >> 1))
        out.append(((c4 & 0x01) << 7) | (c5 << 2) | (c6 >> 3))
    else:
        raise HashsetError(f"invalid base32 length modulo 8: {r}")
    return bytes(out)


def format_hashset(hashes: Mapping[str, bytes]) -> str:
    """Encode a non-empty mapping of algorithm names to digest bytes."""
    if not hashes:
        raise HashsetError("hashset must contain at least one entry")
    entries: list[str] = []
    for alg in sorted(hashes):
        if not ALG_RE.match(alg):
            raise HashsetError(f"invalid algorithm name: {alg!r}")
        digest = hashes[alg]
        if not digest:
            raise HashsetError(f"empty digest for algorithm: {alg!r}")
        entries.append(f"{alg}-{b32_encode(digest)}")
    return ".".join(entries)


def parse_hashset(text: str) -> dict[str, bytes]:
    """Strictly parse and validate a complete Hashset string."""
    if not text or not text.isascii():
        raise HashsetError("hashset must be non-empty ASCII")
    out: dict[str, bytes] = {}
    prev_alg: str | None = None
    for entry in text.split("."):
        if "-" not in entry:
            raise HashsetError(f"entry missing '-' separator: {entry!r}")
        alg, dig = entry.rsplit("-", 1)
        if not ALG_RE.match(alg):
            raise HashsetError(f"invalid algorithm name: {alg!r}")
        if prev_alg is not None and not (prev_alg < alg):
            raise HashsetError(f"unsorted or duplicate algorithm: {alg!r}")
        raw = b32_decode(dig)
        prev_alg = alg
        out[alg] = raw
    return out


def verify_first(
    wire: str,
    data: bytes,
    hashers: Mapping[str, Hasher],
    priority: Sequence[str],
) -> str:
    """Verify the highest-priority supported algorithm present (R1, R2, R3, R5, R6).

    Returns the algorithm name that verified, or raises HashsetError.
    """
    parsed = parse_hashset(wire)
    for alg in priority:
        if alg in parsed:
            if alg not in hashers:
                raise HashsetError(f"missing hasher implementation for {alg!r}")
            computed = hashers[alg](data)
            if not hmac.compare_digest(computed, parsed[alg]):
                raise HashsetError(f"{alg} digest mismatch")
            return alg
    raise HashsetError("no supported hash algorithm present")


def verify_all(
    wire: str,
    data: bytes,
    hashers: Mapping[str, Hasher],
    supported: Set[str],
) -> list[str]:
    """Verify EVERY supported algorithm present, ignoring unknown ones (R4, R7).

    Returns the list of verified algorithm names, or raises HashsetError if none
    are present or if ANY selected algorithm mismatches.
    """
    parsed = parse_hashset(wire)
    selected = [alg for alg in parsed if alg in supported]
    if not selected:
        raise HashsetError("no supported hash algorithm present")
    for alg in selected:
        if alg not in hashers:
            raise HashsetError(f"missing hasher implementation for {alg!r}")
        computed = hashers[alg](data)
        if not hmac.compare_digest(computed, parsed[alg]):
            raise HashsetError(f"{alg} digest mismatch")
    return selected
