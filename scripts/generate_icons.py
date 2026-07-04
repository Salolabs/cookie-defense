#!/usr/bin/env python3
"""Generate placeholder toolbar icons (brown cookie + red 'blocked' slash) as raw PNGs.

No external dependencies (no Pillow) — writes PNG chunks by hand so this
runs in any plain Python 3 environment.
"""
import struct
import zlib
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent.parent / "extension" / "icons"

COOKIE = (196, 132, 62, 255)   # brown
CRUMB = (120, 74, 30, 255)     # dark brown crumb dots
SLASH = (196, 40, 40, 255)     # red "blocked" slash
TRANSPARENT = (0, 0, 0, 0)


def make_icon(size):
    cx = cy = size / 2
    r = size * 0.42
    slash_half_width = max(1.0, size * 0.06)
    pixels = []
    for y in range(size):
        row = []
        for x in range(size):
            dx, dy = x + 0.5 - cx, y + 0.5 - cy
            dist = (dx * dx + dy * dy) ** 0.5
            if dist > r:
                row.append(TRANSPARENT)
                continue
            # crumb dots: a few fixed offsets scaled to icon size
            is_crumb = False
            for ox, oy, cr in ((-0.15, -0.18, 0.09), (0.18, -0.05, 0.07),
                               (-0.05, 0.2, 0.08), (0.15, 0.22, 0.06)):
                ccx, ccy = cx + ox * size, cy + oy * size
                if (x + 0.5 - ccx) ** 2 + (y + 0.5 - ccy) ** 2 <= (cr * size) ** 2:
                    is_crumb = True
                    break
            # diagonal "blocked" slash from top-left to bottom-right
            on_slash = abs(dx - dy) <= slash_half_width
            if on_slash:
                row.append(SLASH)
            elif is_crumb:
                row.append(CRUMB)
            else:
                row.append(COOKIE)
        pixels.append(row)
    return pixels


def write_png(path, pixels):
    size = len(pixels)
    raw = bytearray()
    for row in pixels:
        raw.append(0)  # filter type 0 per scanline
        for (r, g, b, a) in row:
            raw += bytes((r, g, b, a))

    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data +
                struct.pack(">I", zlib.crc32(tag + data) & 0xffffffff))

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    idat = zlib.compress(bytes(raw), 9)
    png = sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")
    path.write_bytes(png)


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for size in (16, 48, 128):
        write_png(OUT_DIR / f"icon{size}.png", make_icon(size))
        print(f"wrote {OUT_DIR / f'icon{size}.png'}")


if __name__ == "__main__":
    main()
