"""Minimal PNG sampling used to estimate how much of a screenshot is blank.

Only 8-bit non-interlaced RGB/RGBA/greyscale images are supported, which
covers ``screencap -p`` output and the Mock screen. Anything else returns
``None`` so the caller reports the signal as unavailable instead of guessing.
"""

from __future__ import annotations

import struct
import zlib


_CHANNELS = {0: 1, 2: 3, 4: 2, 6: 4}


def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def dark_pixel_ratio(
    png: bytes,
    *,
    threshold: int = 24,
    max_bytes: int = 32 * 1024 * 1024,
    sample_step: int = 4,
) -> float | None:
    """Return the fraction of sampled pixels whose channels are all below ``threshold``."""
    if not png.startswith(b"\x89PNG\r\n\x1a\n") or len(png) > max_bytes:
        return None
    offset = 8
    width = height = 0
    channels = 0
    idat = bytearray()
    try:
        while offset + 8 <= len(png):
            length, kind = struct.unpack(">I4s", png[offset : offset + 8])
            data = png[offset + 8 : offset + 8 + length]
            offset += 12 + length
            if kind == b"IHDR":
                width, height, depth, color, _, _, interlace = struct.unpack(">IIBBBBB", data)
                if depth != 8 or interlace != 0 or color not in _CHANNELS:
                    return None
                channels = _CHANNELS[color]
            elif kind == b"IDAT":
                idat.extend(data)
            elif kind == b"IEND":
                break
        if not width or not height or not channels:
            return None
        raw = zlib.decompress(bytes(idat))
    except (struct.error, zlib.error, ValueError):
        return None
    stride = width * channels
    if len(raw) < (stride + 1) * height:
        return None
    previous = bytearray(stride)
    dark = sampled = 0
    position = 0
    for row in range(height):
        filter_type = raw[position]
        line = bytearray(raw[position + 1 : position + 1 + stride])
        position += 1 + stride
        if filter_type == 1:
            for i in range(channels, stride):
                line[i] = (line[i] + line[i - channels]) & 0xFF
        elif filter_type == 2:
            for i in range(stride):
                line[i] = (line[i] + previous[i]) & 0xFF
        elif filter_type == 3:
            for i in range(stride):
                left = line[i - channels] if i >= channels else 0
                line[i] = (line[i] + ((left + previous[i]) >> 1)) & 0xFF
        elif filter_type == 4:
            for i in range(stride):
                left = line[i - channels] if i >= channels else 0
                up_left = previous[i - channels] if i >= channels else 0
                line[i] = (line[i] + _paeth(left, previous[i], up_left)) & 0xFF
        elif filter_type != 0:
            return None
        previous = line
        if row % sample_step:
            continue
        color_channels = 3 if channels >= 3 else 1
        for x in range(0, width, sample_step):
            start = x * channels
            sampled += 1
            if all(line[start + c] < threshold for c in range(color_channels)):
                dark += 1
    return dark / sampled if sampled else None
