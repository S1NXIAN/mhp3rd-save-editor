#!/usr/bin/env python3
"""MHP3rd save editor for Monster Hunter Portable 3rd (ULJM-05800).

Edits hunter name, gender, voice and face in MHP3RD.BIN.
No third-party Python packages are needed; the AES layer uses the system
`openssl` command.

Run `python3 mhp3_save_editor.py --selftest` to check the crypto without
touching a save.

The save format offsets and cipher tables are ported from erickdevit/savemud
(MIT). The cipher was originally documented by svanheulen/mhef (GPL-3.0).
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import os
import re
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
import unicodedata
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Save layout (ULJM-05800)
# ---------------------------------------------------------------------------

EXPECTED_SIZE = 1_183_760
INNER_SIZE = EXPECTED_SIZE - 16 - 4 - 20
BACKUP_DIR = Path.home() / ".config/ppsspp/PSP/SAVEDATA/backups/mhp3rd"

CHAR_BASE = 0x800          # character 1
SLOT_STRIDE = 0x60000      # character 2 = +0x60000, character 3 = +0xC0000
NAME_BYTES = 24            # 12 UTF-16 code units
APPEARANCE_REL = 0x1B      # start of the appearance block
APPEARANCE_BYTES = 0x1D    # 0x81B..0x837: fields, details and five RGBA colours
SKIN_REL = 0x28            # skin R/G/B (0x828..0x82A); alpha at 0x82B
GUILD_CARD_REL = 0x585D4   # separate guild-card name copy (relative to CHAR_BASE)
VOICE_MIN, VOICE_MAX = 0, 19
FACE_MIN, FACE_MAX = 0, 10
NAME_MAX_WIDTH = 12        # 6 full-width or 12 half-width characters
SALT = b"VQ(DOdIO9?X3!2GmW#XF"

PSP_CIPHER1 = bytes([
    0x70, 0x44, 0xa3, 0xae, 0xef, 0x5d, 0xa5, 0xf2,
    0x85, 0x7f, 0xf2, 0xd6, 0x94, 0xf5, 0x36, 0x3b,
])
PSP_CIPHER2 = bytes([
    0xec, 0x6d, 0x29, 0x59, 0x26, 0x35, 0xa5, 0x7f,
    0x97, 0x2a, 0x0d, 0xbc, 0xa3, 0x26, 0x33, 0x00,
])
PSP_CIPHER3 = bytes([
    0x5d, 0xc7, 0x11, 0x39, 0xd0, 0x19, 0x38, 0xbc,
    0x02, 0x7f, 0xdd, 0xdc, 0xb0, 0x83, 0x7d, 0x9d,
])
PSP_CIPHER4 = bytes([
    0x03, 0xb3, 0x02, 0xe8, 0x5f, 0xf3, 0x81, 0xb1,
    0x3b, 0x8d, 0xaa, 0x2a, 0x90, 0xff, 0x5e, 0x61,
])
PSP_GAME_KEY = bytes([
    0xe3, 0x05, 0xce, 0xfa, 0xeb, 0x46, 0xb0, 0x31,
    0x85, 0x9a, 0x27, 0x5b, 0xdf, 0x32, 0xd8, 0x63,
])

INNER_ENCODE = bytes([
    0xa9, 0x3c, 0xdd, 0x96, 0xfe, 0x8e, 0x07, 0xcd, 0xdf, 0xa2, 0x87, 0x82, 0xd4, 0x84, 0xb5, 0x7d,
    0xe4, 0xf7, 0xf0, 0xa5, 0x4d, 0x7a, 0x0d, 0x11, 0x3d, 0xff, 0x42, 0xb8, 0x13, 0xfc, 0xd1, 0xf5,
    0x4f, 0x01, 0x02, 0x6c, 0x31, 0x63, 0x37, 0x47, 0x19, 0x22, 0xb9, 0x86, 0xf1, 0x1f, 0x0f, 0x35,
    0xce, 0x28, 0x26, 0x0e, 0x2a, 0x9a, 0x51, 0xb4, 0x91, 0x17, 0x58, 0x53, 0x5c, 0x04, 0xeb, 0x8b,
    0x74, 0x56, 0xb2, 0xe9, 0x9c, 0x30, 0x59, 0x67, 0x97, 0xd3, 0x4c, 0x41, 0xbf, 0x2d, 0xb3, 0x52,
    0x12, 0xfb, 0x7c, 0xa0, 0x09, 0xa6, 0x71, 0xcb, 0x7b, 0x38, 0x10, 0x44, 0x5a, 0x6b, 0x8a, 0x1e,
    0x75, 0x2b, 0x21, 0x5e, 0xda, 0xed, 0x60, 0x7f, 0x8d, 0xc3, 0xa3, 0xea, 0xde, 0x77, 0xef, 0xe0,
    0x29, 0x8c, 0x6e, 0x16, 0x69, 0x0b, 0x0a, 0xa4, 0x20, 0xba, 0x43, 0xca, 0x9d, 0x7e, 0x65, 0x93,
    0x89, 0x6f, 0x9e, 0x95, 0x5f, 0x57, 0x8f, 0x08, 0xbe, 0xe2, 0xdb, 0x6a, 0x70, 0xe6, 0xf8, 0x6d,
    0xcc, 0xe8, 0xcf, 0x9f, 0xf2, 0x3f, 0xaf, 0xfd, 0x1d, 0xf3, 0x4e, 0x68, 0xaa, 0xb7, 0xad, 0x88,
    0x39, 0x3e, 0x76, 0xa1, 0xd6, 0x3b, 0x00, 0xb0, 0xe5, 0xbd, 0x64, 0xc1, 0xc6, 0x4b, 0x2c, 0x15,
    0x79, 0xf9, 0x4a, 0xd8, 0xab, 0x18, 0xc9, 0xd0, 0xd5, 0x50, 0xe7, 0x90, 0xae, 0x3a, 0xa8, 0xbb,
    0xe3, 0xc8, 0x2f, 0x66, 0x61, 0xc2, 0x72, 0xdc, 0xf6, 0x23, 0x54, 0x5b, 0x27, 0x1c, 0x92, 0x83,
    0xc0, 0xc4, 0x81, 0x98, 0x73, 0xec, 0x85, 0x34, 0x36, 0x1a, 0xd2, 0x45, 0xbc, 0xa7, 0x14, 0x9b,
    0xee, 0xc5, 0xb1, 0xac, 0x55, 0x78, 0x48, 0xfa, 0xf4, 0xc7, 0x25, 0x62, 0x5d, 0x0c, 0x40, 0x80,
    0x46, 0x1b, 0xd9, 0x94, 0x49, 0x06, 0xb6, 0xe1, 0x32, 0x03, 0x99, 0x05, 0x33, 0x24, 0x2e, 0xd7,
])

INNER_DECODE = bytes([
    0xa6, 0x21, 0x22, 0xf9, 0x3d, 0xfb, 0xf5, 0x06, 0x87, 0x54, 0x76, 0x75, 0xed, 0x16, 0x33, 0x2e,
    0x5a, 0x17, 0x50, 0x1c, 0xde, 0xaf, 0x73, 0x39, 0xb5, 0x28, 0xd9, 0xf1, 0xcd, 0x98, 0x5f, 0x2d,
    0x78, 0x62, 0x29, 0xc9, 0xfd, 0xea, 0x32, 0xcc, 0x31, 0x70, 0x34, 0x61, 0xae, 0x4d, 0xfe, 0xc2,
    0x45, 0x24, 0xf8, 0xfc, 0xd7, 0x2f, 0xd8, 0x26, 0x59, 0xa0, 0xbd, 0xa5, 0x01, 0x18, 0xa1, 0x95,
    0xee, 0x4b, 0x1a, 0x7a, 0x5b, 0xdb, 0xf0, 0x27, 0xe6, 0xf4, 0xb2, 0xad, 0x4a, 0x14, 0x9a, 0x20,
    0xb9, 0x36, 0x4f, 0x3b, 0xca, 0xe4, 0x41, 0x85, 0x3a, 0x46, 0x5c, 0xcb, 0x3c, 0xec, 0x63, 0x84,
    0x66, 0xc4, 0xeb, 0x25, 0xaa, 0x7e, 0xc3, 0x47, 0x9b, 0x74, 0x8b, 0x5d, 0x23, 0x8f, 0x72, 0x81,
    0x8c, 0x56, 0xc6, 0xd4, 0x40, 0x60, 0xa2, 0x6d, 0xe5, 0xb0, 0x15, 0x58, 0x52, 0x0f, 0x7d, 0x67,
    0xef, 0xd2, 0x0b, 0xcf, 0x0d, 0xd6, 0x2b, 0x0a, 0x9f, 0x80, 0x5e, 0x3f, 0x71, 0x68, 0x05, 0x86,
    0xbb, 0x38, 0xce, 0x7f, 0xf3, 0x83, 0x03, 0x48, 0xd3, 0xfa, 0x35, 0xdf, 0x44, 0x7c, 0x82, 0x93,
    0x53, 0xa3, 0x09, 0x6a, 0x77, 0x13, 0x55, 0xdd, 0xbe, 0x00, 0x9c, 0xb4, 0xe3, 0x9e, 0xbc, 0x96,
    0xa7, 0xe2, 0x42, 0x4e, 0x37, 0x0e, 0xf6, 0x9d, 0x1b, 0x2a, 0x79, 0xbf, 0xdc, 0xa9, 0x88, 0x4c,
    0xd0, 0xab, 0xc5, 0x69, 0xd1, 0xe1, 0xac, 0xe9, 0xc1, 0xb6, 0x7b, 0x57, 0x90, 0x07, 0x30, 0x92,
    0xb7, 0x1e, 0xda, 0x49, 0x0c, 0xb8, 0xa4, 0xff, 0xb3, 0xf2, 0x64, 0x8a, 0xc7, 0x02, 0x6c, 0x08,
    0x6f, 0xf7, 0x89, 0xc0, 0x10, 0xa8, 0x8d, 0xba, 0x91, 0x43, 0x6b, 0x3e, 0xd5, 0x65, 0xe0, 0x6e,
    0x12, 0x2c, 0x94, 0x99, 0xe8, 0x1f, 0xc8, 0x11, 0x8e, 0xb1, 0xe7, 0x51, 0x1d, 0x97, 0x04, 0x19,
])


# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------

def _aes(data: bytes, key: bytes, decrypt: bool) -> bytes:
    """AES-128-CBC with a zero IV. One block is plain AES."""
    if len(data) % 16:
        raise ValueError("AES input is not block-aligned")
    cmd = [
        "openssl", "enc", "-aes-128-cbc", "-nopad",
        "-K", key.hex(), "-iv", "00" * 16,
    ]
    if decrypt:
        cmd.insert(2, "-d")
    try:
        result = subprocess.run(
            cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
    except FileNotFoundError as exc:
        raise RuntimeError("openssl is not installed") from exc
    if result.returncode != 0:
        message = result.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"openssl failed: {message}")
    if len(result.stdout) != len(data):
        raise RuntimeError("openssl returned an unexpected length")
    return result.stdout


def _xor_stream(data: bytes, seed: int) -> bytes:
    """The XOR part of the Monster Hunter save cipher (symmetric)."""
    out = bytearray(data)
    key0 = (seed >> 16) or 0xDFA3
    key1 = (seed & 0xFFFF) or 0x215F
    unpack = struct.unpack_from
    pack = struct.pack_into
    for offset in range(0, len(out) - 3, 4):
        key0 = (key0 * 0xDFA3) % 0xFFEF
        key1 = (key1 * 0x215F) % 0xFF8F
        value = unpack("<I", out, offset)[0] ^ ((key0 << 16) | key1)
        pack("<I", out, offset, value & 0xFFFFFFFF)
    return bytes(out)


def psp_decrypt(data: bytes) -> bytes:
    if len(data) < 32 or len(data) % 16:
        raise ValueError("not a PSP savedata file")
    key_header = bytearray(data[:16])
    for i in range(16):
        key_header[i] ^= PSP_CIPHER2[i] ^ PSP_GAME_KEY[i]
    xor_key = bytearray(_aes(bytes(key_header), PSP_CIPHER3, True))
    for i in range(12):
        xor_key[i] ^= PSP_CIPHER1[i]

    blocks = len(data) // 16 - 1
    stream_input = bytearray(blocks * 16)
    for counter in range(1, blocks + 1):
        offset = (counter - 1) * 16
        stream_input[offset:offset + 12] = xor_key[:12]
        struct.pack_into("<I", stream_input, offset + 12, counter)
    stream = _aes(bytes(stream_input), PSP_CIPHER4, True)

    plain = bytearray(data[16:])
    for i in range(len(plain)):
        plain[i] ^= stream[i]
    return bytes(plain)


def psp_encrypt(data: bytes) -> bytes:
    if len(data) % 16:
        raise ValueError("PSP payload is not block-aligned")
    xor_key = bytearray(os.urandom(16))
    blocks = len(data) // 16
    stream_input = bytearray(blocks * 16)
    for counter in range(1, blocks + 1):
        offset = (counter - 1) * 16
        stream_input[offset:offset + 12] = xor_key[:12]
        struct.pack_into("<I", stream_input, offset + 12, counter)
    stream = _aes(bytes(stream_input), PSP_CIPHER4, True)

    encrypted = bytearray(data)
    for i in range(len(encrypted)):
        encrypted[i] ^= stream[i]

    header_key = bytearray(xor_key)
    for i in range(12):
        header_key[i] ^= PSP_CIPHER1[i]
    header = bytearray(_aes(bytes(header_key), PSP_CIPHER3, False))
    for i in range(16):
        header[i] ^= PSP_CIPHER2[i] ^ PSP_GAME_KEY[i]
    return bytes(header) + bytes(encrypted)


def inner_decrypt(outer: bytes) -> bytes:
    if len(outer) < 24 or len(outer) % 16:
        raise ValueError("bad inner save size")
    seed_bytes = outer[-4:].translate(INNER_DECODE).translate(INNER_DECODE)
    seed = struct.unpack("<I", seed_bytes)[0]
    plain = outer[:-4].translate(INNER_DECODE)
    plain = _xor_stream(plain, seed).translate(INNER_DECODE)

    expected = plain[-20:]
    payload = plain[:-20]
    if hashlib.sha1(payload[:-12] + SALT).digest() != expected:
        raise ValueError("SHA-1 check failed (damaged save or wrong format)")
    return payload


def inner_encrypt(payload: bytes) -> bytes:
    if len(payload) != INNER_SIZE:
        raise ValueError(f"expected a {INNER_SIZE}-byte payload, got {len(payload)}")
    digest = hashlib.sha1(payload[:-12] + SALT).digest()
    hashed = payload + digest
    seed = secrets.randbelow(0x10000)
    encoded = _xor_stream(hashed.translate(INNER_ENCODE), seed).translate(INNER_ENCODE)
    seed_bytes = struct.pack("<I", seed).translate(INNER_ENCODE).translate(INNER_ENCODE)
    return encoded + seed_bytes


def decrypt_save(raw: bytes) -> bytes:
    if len(raw) != EXPECTED_SIZE:
        raise ValueError(
            f"expected {EXPECTED_SIZE} bytes (ULJM-05800), got {len(raw)}"
        )
    return inner_decrypt(psp_decrypt(raw))


def encrypt_save(payload: bytes) -> bytes:
    return psp_encrypt(inner_encrypt(payload))


# ---------------------------------------------------------------------------
# Character fields
# ---------------------------------------------------------------------------

def slot_base(slot: int) -> int:
    if slot not in (1, 2, 3):
        raise ValueError("slot must be 1, 2 or 3")
    return CHAR_BASE + (slot - 1) * SLOT_STRIDE


def display_width(text: str) -> int:
    return sum(2 if unicodedata.east_asian_width(c) in ("W", "F") else 1 for c in text)


def _read_name_at(payload: bytes, offset: int) -> str:
    text = payload[offset:offset + NAME_BYTES].decode("utf-16-le", errors="replace")
    text = text.split("\x00", 1)[0]
    # The game may store full-width ASCII; show it normally.
    return "".join(
        chr(ord(c) - 0xFEE0) if 0xFF01 <= ord(c) <= 0xFF5E else c
        for c in text
    )


def validate_name(name: str) -> bytes:
    if not name:
        raise ValueError("name cannot be empty")
    if "\x00" in name or any(ord(c) < 0x20 for c in name):
        raise ValueError("name contains a control character")
    if any(ord(c) > 0xFFFF for c in name):
        raise ValueError("only BMP characters are supported")
    encoded = name.encode("utf-16-le")
    if len(encoded) > NAME_BYTES:
        raise ValueError("name is longer than 12 characters")
    if display_width(name) > NAME_MAX_WIDTH:
        raise ValueError("name is too wide (max 6 full-width or 12 half-width)")
    return encoded


def _write_name_at(payload: bytearray, offset: int, name: str) -> None:
    encoded = validate_name(name)
    payload[offset:offset + NAME_BYTES] = (
        encoded + b"\x00" * (NAME_BYTES - len(encoded))
    )


def read_name(payload: bytes, slot: int) -> str:
    return _read_name_at(payload, slot_base(slot))


def write_name(payload: bytearray, slot: int, name: str) -> None:
    _write_name_at(payload, slot_base(slot), name)


def read_guild_name(payload: bytes, slot: int) -> str:
    return _read_name_at(payload, slot_base(slot) + GUILD_CARD_REL)


def write_guild_name(payload: bytearray, slot: int, name: str) -> None:
    _write_name_at(payload, slot_base(slot) + GUILD_CARD_REL, name)


def read_appearance(payload: bytes, slot: int) -> dict[str, int]:
    offset = slot_base(slot) + APPEARANCE_REL
    return {
        "gender": payload[offset],
        "voice": payload[offset + 1],
        "face": payload[offset + 3],
    }


def read_skin(payload: bytes, slot: int) -> tuple[int, int, int]:
    offset = slot_base(slot) + SKIN_REL
    return payload[offset], payload[offset + 1], payload[offset + 2]


def skin_hex(payload: bytes, slot: int) -> str:
    red, green, blue = read_skin(payload, slot)
    return f"#{red:02X}{green:02X}{blue:02X}"


def hex_to_rgb(value: str) -> tuple[int, int, int]:
    value = value.lstrip("#")
    return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)


def apply_edits(
    payload: bytes,
    slot: int,
    *,
    name: str | None = None,
    gender: int | None = None,
    voice: int | None = None,
    face: int | None = None,
    skin: tuple[int, int, int] | None = None,
) -> bytes:
    raw = bytearray(payload)
    if name is not None:
        write_name(raw, slot, name)
        # The guild card keeps its own copy of the name.
        write_guild_name(raw, slot, name)
    offset = slot_base(slot) + APPEARANCE_REL
    for label, value, low, high in (
        ("gender", gender, 0, 1),
        ("voice", voice, VOICE_MIN, VOICE_MAX),
        ("face", face, FACE_MIN, FACE_MAX),
    ):
        if value is None:
            continue
        if not isinstance(value, int) or not low <= value <= high:
            raise ValueError(f"{label} must be {low}-{high}")
    if gender is not None:
        raw[offset] = gender
    if voice is not None:
        raw[offset + 1] = voice
    if face is not None:
        raw[offset + 3] = face
    if skin is not None:
        try:
            red, green, blue = skin
        except (TypeError, ValueError) as exc:
            raise ValueError("skin must be an RGB triple (0-255)") from exc
        if any(
            not isinstance(value, int) or not 0 <= value <= 255
            for value in (red, green, blue)
        ):
            raise ValueError("skin must be an RGB triple (0-255)")
        skin_offset = slot_base(slot) + SKIN_REL
        raw[skin_offset:skin_offset + 3] = bytes((red, green, blue))
    return bytes(raw)


def copy_appearance(payload: bytes, target_slot: int, source_slot: int) -> bytes:
    if target_slot == source_slot:
        raise ValueError("source and target must be different slots")
    for label, slot in (("target", target_slot), ("source", source_slot)):
        if not read_name(payload, slot):
            raise ValueError(f"{label} slot {slot} is empty")
    raw = bytearray(payload)
    source = slot_base(source_slot) + APPEARANCE_REL
    target = slot_base(target_slot) + APPEARANCE_REL
    raw[target:target + APPEARANCE_BYTES] = (
        raw[source:source + APPEARANCE_BYTES]
    )
    return bytes(raw)


def delete_slot(payload: bytes, slot: int) -> bytes:
    """Empty a character slot exactly like an unused slot (all zeroes)."""
    if not read_name(payload, slot):
        raise ValueError(f"slot {slot} is already empty")
    raw = bytearray(payload)
    base = slot_base(slot)
    raw[base:base + SLOT_STRIDE] = b"\x00" * SLOT_STRIDE
    return bytes(raw)


# ---------------------------------------------------------------------------
# Console UI
# ---------------------------------------------------------------------------

def find_save() -> Path | None:
    candidates = [
        Path.home() / ".config/ppsspp/PSP/SAVEDATA/ULJM05800/MHP3RD.BIN",
        Path.home() / ".var/app/org.ppsspp.PPSSPP/config/ppsspp/PSP/SAVEDATA/ULJM05800/MHP3RD.BIN",
        Path.cwd() / "MHP3RD.BIN",
    ]
    for path in candidates:
        if path.is_file():
            return path
    return None


def gender_text(value: int) -> str:
    return {0: "M", 1: "F"}.get(value, "?")


RESET = "\x1b[0m"
BOLD = "\x1b[1m"
GRAY = "\x1b[90m"
CYAN = "\x1b[36m"
GREEN = "\x1b[92m"
YELLOW = "\x1b[93m"
RED = "\x1b[91m"
BLUE = "\x1b[94m"
MAGENTA = "\x1b[95m"

COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ
UNICODE = (
    (sys.stdout.encoding or "").lower().replace("-", "").startswith("utf")
    and os.environ.get("TERM") != "dumb"
)

H = "─" if UNICODE else "-"
V = "│" if UNICODE else "|"
TL, TM, TR = ("┌", "┬", "┐") if UNICODE else ("+", "+", "+")
ML, MM, MR = ("├", "┼", "┤") if UNICODE else ("+", "+", "+")
BL, BM, BR = ("└", "┴", "┘") if UNICODE else ("+", "+", "+")
EMPTY = "—" if UNICODE else "-"
DOT = "·" if UNICODE else "-"
ARROW = "→" if UNICODE else "->"
CHECK = "✓" if UNICODE else "[OK]"
PROMPT = "›" if UNICODE else ">"
RULE_WIDTH = 57


def style(text: str, *codes: str) -> str:
    if not COLOR or not codes:
        return text
    return "".join(codes) + text + RESET


def pad(text: str, width: int, align: str = "left") -> str:
    gap = max(0, width - display_width(text))
    if align == "right":
        return " " * gap + text
    if align == "center":
        left = gap // 2
        return " " * left + text + " " * (gap - left)
    return text + " " * gap


def swatch(rgb: tuple[int, int, int]) -> str:
    if not COLOR:
        return ""
    red, green, blue = rgb
    return f"\x1b[48;2;{red};{green};{blue}m  {RESET}"


def display_path(path: Path) -> str:
    try:
        return "~/" + str(path.relative_to(Path.home()))
    except ValueError:
        return str(path)


def gender_style(value: int) -> tuple[str, ...]:
    if value == 0:
        return (BOLD, BLUE)
    if value == 1:
        return (BOLD, MAGENTA)
    return (GRAY,)


def print_header(save_path: Path) -> None:
    print()
    print(style("MHP3rd Save Editor", BOLD, CYAN))
    print(style(f"Monster Hunter Portable 3rd {DOT} ULJM-05800", GRAY))
    print(style(H * RULE_WIDTH, GRAY))
    print(style("Save  ", GRAY) + style(display_path(save_path), BOLD))
    print(style("Size  ", GRAY) + style(f"{EXPECTED_SIZE:,} bytes", BOLD))
    print()


def render_table(
    headers: list[str],
    rows: list[list[tuple[str, tuple[str, ...]]]],
    aligns: list[str],
    min_widths: list[int],
) -> None:
    widths = [
        max(min_widths[i], display_width(headers[i]))
        for i in range(len(headers))
    ]
    for row in rows:
        for i, (text, _) in enumerate(row):
            widths[i] = max(widths[i], display_width(text))

    def border(left: str, middle: str, right: str) -> str:
        line = left + middle.join(H * (w + 2) for w in widths) + right
        return style(line, GRAY)

    def row_line(
        cells: list[tuple[str, tuple[str, ...]]], header: bool = False
    ) -> str:
        parts = []
        for (text, codes), width, align in zip(cells, widths, aligns):
            cell = " " + pad(text, width, align) + " "
            parts.append(style(cell, *(BOLD,) if header else codes))
        separator = style(V, GRAY)
        return separator + separator.join(parts) + separator

    print(border(TL, TM, TR))
    print(row_line([(h, ()) for h in headers], header=True))
    print(border(ML, MM, MR))
    for row in rows:
        print(row_line(row))
    print(border(BL, BM, BR))


def print_table(payload: bytes) -> None:
    headers = ["Slot", "Name", "Gender", "Voice", "Face", "Skin"]
    aligns = ["center", "left", "center", "center", "center", "center"]
    min_widths = [4, 12, 6, 5, 4, 7]
    rows: list[list[tuple[str, tuple[str, ...]]]] = []

    for slot in (1, 2, 3):
        name = read_name(payload, slot)
        if not name:
            rows.append(
                [
                    (str(slot), (GRAY,)),
                    (EMPTY, (GRAY,)),
                    (EMPTY, (GRAY,)),
                    (EMPTY, (GRAY,)),
                    (EMPTY, (GRAY,)),
                    (EMPTY, (GRAY,)),
                ]
            )
            continue
        appearance = read_appearance(payload, slot)
        rows.append(
            [
                (str(slot), (GRAY,)),
                (name, (BOLD,)),
                (
                    gender_text(appearance["gender"]),
                    gender_style(appearance["gender"]),
                ),
                (str(appearance["voice"] + 1), (BOLD,)),
                (str(appearance["face"] + 1), (BOLD,)),
                (skin_hex(payload, slot), (BOLD,)),
            ]
        )

    render_table(headers, rows, aligns, min_widths)


def print_note() -> None:
    print(
        style(
            f"1-based: voice 1-20 {DOT} face 1-11",
            GRAY,
        )
    )


def print_menu(payload: bytes, dirty: bool) -> None:
    print()
    print(style("Character slots", BOLD))
    for slot in (1, 2, 3):
        name = read_name(payload, slot)
        label = f"Edit slot {slot}"
        if name:
            print(
                f"  {style(str(slot), BOLD, CYAN)}  {label:<14}"
                f"{style(name, GRAY)}"
            )
        else:
            print(style(f"  {slot}  {label:<14}empty", GRAY))
    print()
    print(style("Actions", BOLD))
    if dirty:
        print(
            f"  {style('s', BOLD, GREEN)}  Save changes  "
            f"{style('unsaved', BOLD, YELLOW)}"
        )
    else:
        print(style("  s  Save changes", GRAY))
    print(f"  {style('m', BOLD, CYAN)}  More actions")
    print(f"  {style('q', BOLD, GRAY)}  Quit")
    print()


def error(text: str) -> None:
    print(style("Error:", BOLD, RED), text)


def warning(text: str) -> None:
    print(style("Warning:", BOLD, YELLOW), text)


def success(text: str) -> None:
    print(style(CHECK, BOLD, GREEN), text)


def ask_text(label: str, current: str) -> str:
    shown = current if current else "empty"
    value = input(
        f"{style(label, BOLD)} [{style(shown, GRAY)}]: "
    ).strip()
    return current if value == "" else value


def ask_hex(label: str, current: str) -> str:
    while True:
        value = input(
            f"{style(label, BOLD)} [{style(current, GRAY)}]: "
        ).strip()
        if value == "":
            return current
        candidate = value.lstrip("#").upper()
        if len(candidate) == 6 and all(
            c in "0123456789ABCDEF" for c in candidate
        ):
            return "#" + candidate
        print(
            style(
                "  Enter a 6-digit hex colour, e.g. E49A67.",
                YELLOW,
            )
        )


def ask_int(label: str, current: int, low: int, high: int) -> int:
    while True:
        value = input(
            f"{style(label, BOLD)} {style(f'{low}-{high}', GRAY)} "
            f"[{style(str(current), BOLD)}]: "
        ).strip()
        if value == "":
            return current
        try:
            number = int(value, 10)
        except ValueError:
            print(style(f"  Enter a number from {low} to {high}.", YELLOW))
            continue
        if low <= number <= high:
            return number
        print(style(f"  Enter a number from {low} to {high}.", YELLOW))


def ask_gender(current: int) -> int:
    while True:
        shown = gender_text(current)
        value = input(
            f"{style('Gender', BOLD)} {style('[M/F]', GRAY)} "
            f"[{style(shown, *gender_style(current))}]: "
        ).strip().lower()
        if value == "" and current in (0, 1):
            return current
        if value in ("m", "male", "0"):
            return 0
        if value in ("f", "female", "1"):
            return 1
        print(style("  Enter M or F.", YELLOW))


def edit_slot(payload: bytes, slot: int) -> bytes:
    name = read_name(payload, slot)
    if not name:
        warning(f"Slot {slot} is empty; there is no character to edit.")
        return payload

    appearance = read_appearance(payload, slot)
    print()
    print(style(f"Edit slot {slot}", BOLD, CYAN))
    print(style(H * RULE_WIDTH, GRAY))
    for label, value, codes in (
        ("Hunter name", name, (BOLD,)),
        (
            "Gender",
            gender_text(appearance["gender"]),
            gender_style(appearance["gender"]),
        ),
        ("Voice", str(appearance["voice"] + 1), (BOLD,)),
        ("Face", str(appearance["face"] + 1), (BOLD,)),
        ("Skin", skin_hex(payload, slot), (BOLD,)),
    ):
        prefix = ""
        if label == "Skin":
            prefix = swatch(read_skin(payload, slot))
            if prefix:
                prefix += " "
        print(style(pad(label, 12), GRAY) + prefix + style(value, *codes))
    if slot != 1:
        print(style("  Appearance offsets for slots 2/3 are less tested.", GRAY))
    print()
    print(style("Press Enter to keep the current value.", GRAY))
    print()

    while True:
        new_name = ask_text("Hunter name", name)
        if new_name == name:
            break
        try:
            validate_name(new_name)
        except ValueError as exc:
            print(style(f"  {str(exc).capitalize()}", YELLOW))
            continue
        break

    new_gender = ask_gender(appearance["gender"])
    new_voice = ask_int("Voice", appearance["voice"] + 1, 1, VOICE_MAX + 1) - 1
    new_face = ask_int("Face", appearance["face"] + 1, 1, FACE_MAX + 1) - 1
    old_skin = skin_hex(payload, slot)
    new_skin = ask_hex("Skin", old_skin)

    changes: list[tuple[str, str, str]] = []
    if new_name != name:
        changes.append(("Hunter name", name, new_name))
    if new_gender != appearance["gender"]:
        changes.append(
            ("Gender", gender_text(appearance["gender"]), gender_text(new_gender))
        )
    if new_voice != appearance["voice"]:
        changes.append(
            ("Voice", str(appearance["voice"] + 1), str(new_voice + 1))
        )
    if new_face != appearance["face"]:
        changes.append(
            ("Face", str(appearance["face"] + 1), str(new_face + 1))
        )
    if new_skin != old_skin:
        changes.append(("Skin", old_skin, new_skin))

    print()
    if changes:
        print(style("Changes", BOLD))
        for label, old, new in changes:
            print(
                "  " + style(pad(label, 12), GRAY)
                + style(old, GRAY) + style(f" {ARROW} ", GRAY)
                + style(new, BOLD, GREEN)
            )
    else:
        print(style("No changes.", GRAY))

    kwargs: dict[str, object] = {}
    if new_name != name:
        kwargs["name"] = new_name
    if new_gender != appearance["gender"]:
        kwargs["gender"] = new_gender
    if new_voice != appearance["voice"]:
        kwargs["voice"] = new_voice
    if new_face != appearance["face"]:
        kwargs["face"] = new_face
    if new_skin != old_skin:
        kwargs["skin"] = hex_to_rgb(new_skin)

    if not kwargs:
        return payload
    try:
        return apply_edits(payload, slot, **kwargs)
    except ValueError as exc:
        error(str(exc))
        return payload


def copy_appearance_and_voice(payload: bytes) -> bytes:
    print()
    print(style("Copy appearance + voice", BOLD, CYAN))
    print(style(H * RULE_WIDTH, GRAY))
    for slot in (1, 2, 3):
        name = read_name(payload, slot)
        if name:
            print(f"  {style(str(slot), BOLD, CYAN)}  {name}")
        else:
            print(style(f"  {slot}  empty", GRAY))
    print(style("Copies the full appearance and voice.", GRAY))
    print()

    target = ask_int("Target slot", 1, 1, 3)
    if not read_name(payload, target):
        warning(f"Slot {target} is empty; choose a used slot.")
        return payload

    source_default = 1 if target != 1 else 2
    while True:
        source = ask_int("Source slot", source_default, 1, 3)
        if source == target:
            print(style("  Source must be a different slot.", YELLOW))
            continue
        if not read_name(payload, source):
            print(style(f"  Slot {source} is empty.", YELLOW))
            continue
        break

    current_name = read_name(payload, target)
    while True:
        new_name = ask_text("New name", current_name)
        if new_name == current_name:
            break
        try:
            validate_name(new_name)
        except ValueError as exc:
            print(style(f"  {str(exc).capitalize()}", YELLOW))
            continue
        break

    try:
        updated = copy_appearance(payload, target, source)
        if new_name != current_name:
            updated = apply_edits(updated, target, name=new_name)
    except ValueError as exc:
        error(str(exc))
        return payload

    success(f"Copied appearance + voice from slot {source} to slot {target}.")
    if new_name != current_name:
        print(
            "  " + style(pad("Name", 12), GRAY)
            + style(current_name, GRAY) + style(f" {ARROW} ", GRAY)
            + style(new_name, BOLD, GREEN)
        )
    else:
        print(
            "  " + style(pad("Name", 12), GRAY)
            + style(current_name, BOLD) + style(" (unchanged)", GRAY)
        )

    print()
    print(
        style(
            f"Delete source slot {source}? This empties that character.",
            BOLD,
            YELLOW,
        )
    )
    answer = input(style("Confirm [y/N]: ", BOLD)).strip().lower()
    if answer in ("y", "yes"):
        try:
            updated = delete_slot(updated, source)
        except ValueError as exc:
            error(str(exc))
        else:
            success(f"Deleted source slot {source}.")
    return updated


def create_backup(save_path: Path, backup_dir: Path = BACKUP_DIR) -> Path:
    backup_dir = Path(backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = backup_dir / f"{save_path.name}.bak-{stamp}"
    backup = base
    counter = 1
    while backup.exists():
        backup = base.with_name(f"{base.name}-{counter}")
        counter += 1
    shutil.copy2(save_path, backup)
    if backup.read_bytes() != save_path.read_bytes():
        raise RuntimeError("backup verification failed")
    return backup


def save_payload(
    save_path: Path,
    payload: bytes,
    backup_dir: Path = BACKUP_DIR,
) -> Path:
    raw = encrypt_save(payload)
    if decrypt_save(raw) != payload:
        raise RuntimeError("encrypted save did not verify")
    backup = create_backup(save_path, backup_dir)
    temporary = save_path.with_name(save_path.name + ".tmp")
    try:
        temporary.write_bytes(raw)
        os.replace(temporary, save_path)
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink()
    try:
        if decrypt_save(save_path.read_bytes()) != payload:
            raise RuntimeError("saved file did not verify")
    except Exception:
        shutil.copy2(backup, save_path)
        raise
    return backup


def backup_sort_key(path: Path) -> tuple[str, str]:
    match = re.match(r".+\.bak-(\d{8})-(\d{6})", path.name)
    if match:
        return (match.group(1) + match.group(2), path.name)
    return (
        datetime.fromtimestamp(
            path.stat().st_mtime
        ).strftime("%Y%m%d%H%M%S"),
        path.name,
    )


def list_backups(
    save_name: str = "MHP3RD.BIN", backup_dir: Path = BACKUP_DIR
) -> list[Path]:
    backup_dir = Path(backup_dir)
    if not backup_dir.is_dir():
        return []
    prefix = f"{save_name}.bak-"
    paths = [
        path
        for path in backup_dir.iterdir()
        if path.is_file() and path.name.startswith(prefix)
    ]
    return sorted(paths, key=backup_sort_key, reverse=True)


def backup_label(path: Path) -> str:
    match = re.match(
        r".+\.bak-(\d{8})-(\d{6})(.*)", path.name
    )
    if match:
        try:
            when = datetime.strptime(
                match.group(1) + match.group(2), "%Y%m%d%H%M%S"
            )
            suffix = match.group(3).lstrip("-")
            return when.strftime("%Y-%m-%d %H:%M") + (
                f"  {suffix}" if suffix else ""
            )
        except ValueError:
            pass
    when = datetime.fromtimestamp(
        path.stat().st_mtime
    ).strftime("%Y-%m-%d %H:%M")
    return f"{when}  {path.name}"


def restore_backup(
    save_path: Path,
    backup_path: Path,
    backup_dir: Path = BACKUP_DIR,
) -> tuple[bytes, Path]:
    payload = decrypt_save(backup_path.read_bytes())
    pre_restore = create_backup(save_path, backup_dir)
    temporary = save_path.with_name(save_path.name + ".restore-tmp")
    try:
        shutil.copyfile(backup_path, temporary)
        os.replace(temporary, save_path)
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink()
    try:
        if decrypt_save(save_path.read_bytes()) != payload:
            raise RuntimeError("restored save did not verify")
    except Exception:
        shutil.copy2(pre_restore, save_path)
        raise
    return payload, pre_restore


def ppsspp_running() -> bool:
    proc = Path("/proc")
    if proc.is_dir():
        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                name = (entry / "comm").read_text().strip().lower()
            except OSError:
                continue
            if name in {"ppssppsdl", "ppsspp", "ppssppqt"}:
                return True
        return False

    for name in ("PPSSPPSDL", "ppsspp", "PPSSPPQt"):
        try:
            result = subprocess.run(
                ["pgrep", "-x", name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            continue
        if result.returncode == 0:
            return True
    return False


def require_ppsspp_closed() -> bool:
    if ppsspp_running():
        error("PPSSPP is running. Close it completely, then retry.")
        return False
    return True


def save_changes(save_path: Path, payload: bytes) -> bool:
    print()
    print(style("Save changes", BOLD, CYAN))
    if not require_ppsspp_closed():
        return False
    try:
        backup = save_payload(save_path, payload)
    except Exception as exc:
        error(str(exc))
        print(style("The live save was left in place or restored.", GRAY))
        return False
    success("Saved.")
    print(style("  Backup: ", GRAY) + style(display_path(backup), BOLD))
    return True


def more_actions_menu() -> str | None:
    print()
    print(style("More actions", BOLD, CYAN))
    print(style(H * RULE_WIDTH, GRAY))
    print(f"  {style('c', BOLD, MAGENTA)}  Copy appearance + voice")
    print(f"  {style('r', BOLD, CYAN)}  Restore a backup")
    print(f"  {style('b', BOLD, GRAY)}  Back")
    print()
    while True:
        choice = input(style(f"Select {PROMPT} ", BOLD, CYAN)).strip().lower()
        if choice == "c":
            return "copy"
        if choice == "r":
            return "restore"
        if choice in ("b", "back", "q", "quit", ""):
            return None
        print(style("Choose c, r or b.", GRAY))


def backup_index_for_page(
    choice: str, page: int, page_size: int, count: int
) -> int | None:
    if not choice.isdigit():
        return None
    index = int(choice) - 1
    start = page * page_size
    end = min(start + page_size, count)
    if start <= index < end:
        return index
    return None


def restore_picker(
    save_path: Path, backup_dir: Path = BACKUP_DIR
) -> bytes | None:
    backups = list_backups(save_path.name, backup_dir)
    if not backups:
        print()
        print(style("Restore a backup", BOLD, CYAN))
        print(style("No backups yet.", GRAY))
        return None

    page_size = 10
    page = 0
    while True:
        pages = (len(backups) + page_size - 1) // page_size
        page = min(page, pages - 1)
        print()
        print(style("Restore a backup", BOLD, CYAN))
        print(style(display_path(backup_dir), GRAY))
        print(style(H * RULE_WIDTH, GRAY))
        start = page * page_size
        for index in range(start, min(start + page_size, len(backups))):
            print(f"  {index + 1:>2}  {backup_label(backups[index])}")
        if pages > 1:
            print(style(f"  Page {page + 1}/{pages}", GRAY))
        print()
        if page > 0:
            print(f"  {style('p', BOLD, CYAN)}  Previous page")
        if page < pages - 1:
            print(f"  {style('n', BOLD, CYAN)}  Next page")
        print(f"  {style('b', BOLD, GRAY)}  Back")
        print()
        choice = input(style(f"Select {PROMPT} ", BOLD, CYAN)).strip().lower()
        if choice == "n" and page < pages - 1:
            page += 1
            continue
        if choice == "p" and page > 0:
            page -= 1
            continue
        if choice in ("b", "back", "q", "quit", ""):
            return None
        if not choice.isdigit():
            print(style("Choose a number, n/p, or b.", GRAY))
            continue
        index = backup_index_for_page(choice, page, page_size, len(backups))
        if index is None:
            print(style("That backup number is not on this page.", GRAY))
            continue

        selected = backups[index]
        try:
            payload = decrypt_save(selected.read_bytes())
        except Exception as exc:
            error(f"Could not read that backup: {exc}")
            continue

        print()
        print(style(f"Preview: {backup_label(selected)}", BOLD, CYAN))
        print_table(payload)
        print_note()
        print()
        print(style("Close PPSSPP before restoring.", BOLD, YELLOW))
        print(style("The current save will be backed up first.", GRAY))
        answer = input(
            style("Restore this backup? ", BOLD)
            + style("[y/N]: ", GRAY)
        ).strip().lower()
        if answer in ("y", "yes"):
            if not require_ppsspp_closed():
                continue
            try:
                restored, pre_restore = restore_backup(
                    save_path, selected, backup_dir
                )
            except Exception as exc:
                error(f"Restore failed: {exc}")
                continue
            success("Restored backup.")
            print(
                style("  Pre-restore backup: ", GRAY)
                + style(display_path(pre_restore), BOLD)
            )
            return restored


def interactive_loop(save_path: Path, payload: bytes) -> None:
    baseline = payload
    dirty = False
    print_table(payload)
    print_note()

    while True:
        print_menu(payload, dirty)
        choice = input(style(f"Select {PROMPT} ", BOLD, CYAN)).strip().lower()

        if choice in ("1", "2", "3"):
            slot = int(choice)
            if not read_name(payload, slot):
                warning(f"Slot {slot} is empty; there is no character to edit.")
                continue
            updated = edit_slot(payload, slot)
            if updated != payload:
                payload = updated
                dirty = payload != baseline
                print()
                print_table(payload)
                print_note()
        elif choice == "m":
            action = more_actions_menu()
            if action == "copy":
                updated = copy_appearance_and_voice(payload)
                if updated != payload:
                    payload = updated
                    dirty = payload != baseline
                    print()
                    print_table(payload)
                    print_note()
            elif action == "restore":
                restored = restore_picker(save_path)
                if restored is not None:
                    payload = restored
                    baseline = payload
                    dirty = False
                    print()
                    print_table(payload)
                    print_note()
        elif choice == "s":
            if not dirty:
                print(style("No changes to save.", GRAY))
                continue
            if save_changes(save_path, payload):
                return
        elif choice in ("q", "quit", "exit"):
            if dirty:
                answer = input(
                    style("Discard unsaved changes? ", BOLD, YELLOW)
                    + style("[y/N]: ", GRAY)
                ).strip().lower()
                if answer not in ("y", "yes"):
                    continue
            return
        else:
            print(style("Choose 1-3, s, m or q.", GRAY))


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _sample_payload() -> bytes:
    payload = bytearray(os.urandom(INNER_SIZE))
    encoded = "Tester".encode("utf-16-le")
    payload[CHAR_BASE:CHAR_BASE + NAME_BYTES] = (
        encoded + b"\x00" * (NAME_BYTES - len(encoded))
    )
    payload[CHAR_BASE + APPEARANCE_REL:CHAR_BASE + APPEARANCE_REL + 4] = (
        bytes([1, 5, 3, 9])
    )
    guild = "Guild1".encode("utf-16-le")
    payload[
        CHAR_BASE + GUILD_CARD_REL:
        CHAR_BASE + GUILD_CARD_REL + NAME_BYTES
    ] = guild + b"\x00" * (NAME_BYTES - len(guild))
    for slot in (2, 3):
        offset = slot_base(slot) + GUILD_CARD_REL
        payload[offset:offset + NAME_BYTES] = b"\x00" * NAME_BYTES
    return bytes(payload)


def _test_aes_vector() -> None:
    key = bytes(range(16))
    plain = bytes.fromhex("00112233445566778899aabbccddeeff")
    cipher = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert _aes(plain, key, False) == cipher
    assert _aes(cipher, key, True) == plain


def _test_tables_inverse() -> None:
    assert all(INNER_ENCODE[INNER_DECODE[i]] == i for i in range(256))


def _test_cipher_roundtrip(original: bytes) -> None:
    raw = encrypt_save(original)
    assert len(raw) == EXPECTED_SIZE
    assert decrypt_save(raw) == original
    assert read_name(original, 1) == "Tester"
    assert read_guild_name(original, 1) == "Guild1"
    assert read_appearance(original, 1) == {
        "gender": 1, "voice": 5, "face": 9,
    }


def _test_edit_fields(original: bytes) -> None:
    edited = apply_edits(
        original, 1, name="Edited",
        gender=0, voice=0, face=0, skin=(255, 0, 0),
    )
    assert read_name(edited, 1) == "Edited"
    assert read_guild_name(edited, 1) == "Edited"
    assert read_appearance(edited, 1) == {
        "gender": 0, "voice": 0, "face": 0,
    }
    assert read_skin(edited, 1) == (255, 0, 0)
    assert skin_hex(edited, 1) == "#FF0000"
    assert hex_to_rgb("#112233") == (0x11, 0x22, 0x33)
    assert decrypt_save(encrypt_save(edited)) == edited

    appearance_only = apply_edits(original, 1, gender=0)
    assert read_guild_name(appearance_only, 1) == "Guild1"
    assert read_skin(appearance_only, 1) == read_skin(original, 1)

    try:
        apply_edits(original, 1, skin=(256, 0, 0))
    except ValueError:
        pass
    else:
        raise AssertionError("invalid skin was accepted")


def _test_copy(original: bytes) -> None:
    with_source = apply_edits(
        original, 2, name="Second", gender=0, voice=10, face=8
    )
    copied = copy_appearance(with_source, 1, 2)
    assert read_name(copied, 1) == "Tester"
    assert read_guild_name(copied, 1) == "Guild1"
    assert read_appearance(copied, 1) == read_appearance(with_source, 2)
    assert (
        copied[
            slot_base(1) + APPEARANCE_REL:
            slot_base(1) + APPEARANCE_REL + APPEARANCE_BYTES
        ]
        == with_source[
            slot_base(2) + APPEARANCE_REL:
            slot_base(2) + APPEARANCE_REL + APPEARANCE_BYTES
        ]
    )
    assert read_skin(copied, 1) == read_skin(with_source, 2)

    renamed = apply_edits(copied, 1, name="Cloned")
    assert read_name(renamed, 1) == "Cloned"
    assert read_guild_name(renamed, 1) == "Cloned"
    assert read_appearance(renamed, 1) == read_appearance(with_source, 2)

    empty = bytearray(original)
    empty[slot_base(3):slot_base(3) + NAME_BYTES] = b"\x00" * NAME_BYTES
    for target, from_slot, data in (
        (1, 1, original),
        (1, 3, bytes(empty)),
    ):
        try:
            copy_appearance(data, target, from_slot)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid copy was accepted")


def _test_delete(original: bytes) -> None:
    with_source = apply_edits(original, 2, name="Second")
    deleted = delete_slot(with_source, 2)
    assert read_name(deleted, 2) == ""
    assert read_guild_name(deleted, 2) == ""
    assert not any(deleted[slot_base(2):slot_base(2) + SLOT_STRIDE])
    assert read_name(deleted, 1) == "Tester"
    try:
        delete_slot(deleted, 2)
    except ValueError:
        pass
    else:
        raise AssertionError("empty slot deletion was accepted")


def _test_names(original: bytes) -> None:
    for slot in (2, 3):
        changed = apply_edits(original, slot, name=f"Slot{slot}")
        assert read_name(changed, slot) == f"Slot{slot}"
        assert read_guild_name(changed, slot) == f"Slot{slot}"

    full_width = bytearray(original)
    full_width[CHAR_BASE:CHAR_BASE + NAME_BYTES] = (
        "\uff50iroca".encode("utf-16-le")
        + b"\x00" * (NAME_BYTES - 12)
    )
    assert read_name(bytes(full_width), 1) == "piroca"

    try:
        apply_edits(original, 1, name="\u3042" * 7)
    except ValueError:
        pass
    else:
        raise AssertionError("wide name was accepted")


def _test_backup_restore(original: bytes) -> None:
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
        temp = Path(temp_dir)
        backup_dir = temp / "backups"
        save_file = temp / "MHP3RD.BIN"
        save_file.write_bytes(encrypt_save(original))

        edited_payload = apply_edits(original, 1, name="BackupTest")
        backup = save_payload(
            save_file, edited_payload, backup_dir=backup_dir
        )
        assert backup.parent == backup_dir
        assert decrypt_save(save_file.read_bytes()) == edited_payload
        assert decrypt_save(backup.read_bytes()) == original

        restored, pre_restore = restore_backup(
            save_file, backup, backup_dir=backup_dir
        )
        assert restored == original
        assert decrypt_save(save_file.read_bytes()) == original
        assert pre_restore.parent == backup_dir
        assert decrypt_save(pre_restore.read_bytes()) == edited_payload

        backups = list_backups("MHP3RD.BIN", backup_dir)
        assert len(backups) == 2
        assert all(path.is_file() for path in backups)


def _test_backup_listing() -> None:
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
        backup_dir = Path(temp_dir)
        (backup_dir / "OTHER.BIN.bak-20260101-000000").write_bytes(b"x")
        (backup_dir / "MHP3RD.BIN.bak-20260101-000000").write_bytes(b"x")
        (backup_dir / "MHP3RD.BIN.bak-20250101-000000").write_bytes(b"x")
        assert len(list_backups("OTHER.BIN", backup_dir)) == 1
        assert [
            path.name for path in list_backups("MHP3RD.BIN", backup_dir)
        ] == [
            "MHP3RD.BIN.bak-20260101-000000",
            "MHP3RD.BIN.bak-20250101-000000",
        ]
        assert list_backups("MISSING.BIN", backup_dir) == []


def _test_picker_page() -> None:
    assert backup_index_for_page("1", 0, 10, 12) == 0
    assert backup_index_for_page("10", 0, 10, 12) == 9
    assert backup_index_for_page("11", 0, 10, 12) is None
    assert backup_index_for_page("11", 1, 10, 12) == 10
    assert backup_index_for_page("12", 1, 10, 12) == 11
    assert backup_index_for_page("1", 1, 10, 12) is None
    assert backup_index_for_page("x", 0, 10, 12) is None


def _test_ppsspp_guard() -> None:
    original = ppsspp_running
    try:
        globals()["ppsspp_running"] = lambda: True
        with contextlib.redirect_stdout(io.StringIO()):
            assert require_ppsspp_closed() is False
        globals()["ppsspp_running"] = lambda: False
        assert require_ppsspp_closed() is True
    finally:
        globals()["ppsspp_running"] = original


def _test_ppsspp_probe() -> None:
    assert isinstance(ppsspp_running(), bool)


def run_selftest() -> int:
    original = _sample_payload()
    tests = (
        ("AES-128-CBC vector", _test_aes_vector),
        ("substitution tables", _test_tables_inverse),
        (
            "inner/outer cipher round-trip",
            lambda: _test_cipher_roundtrip(original),
        ),
        ("fields, skin and limits", lambda: _test_edit_fields(original)),
        ("copy appearance + voice", lambda: _test_copy(original)),
        ("delete source slot", lambda: _test_delete(original)),
        ("names and slot limits", lambda: _test_names(original)),
        ("backup and restore", lambda: _test_backup_restore(original)),
        ("backup list filter and order", _test_backup_listing),
        ("restore picker pagination", _test_picker_page),
        ("PPSSPP guard", _test_ppsspp_guard),
        ("PPSSPP process probe", _test_ppsspp_probe),
    )
    for name, test in tests:
        test()
        print(style(f"  {CHECK} {name}", GREEN))
    print(style("selftest: PASS", BOLD, GREEN))
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Edit hunter name, gender, voice, face and skin tone in an "
            "MHP3rd save."
        )
    )
    parser.add_argument(
        "save", nargs="?",
        help="path to MHP3RD.BIN (auto-detected PPSSPP save if omitted)",
    )
    parser.add_argument(
        "--check", action="store_true",
        help="show the current characters and exit without writing",
    )
    parser.add_argument(
        "--selftest", action="store_true",
        help="run the built-in crypto and round-trip tests",
    )
    args = parser.parse_args(argv)

    if args.selftest:
        return run_selftest()

    if args.save:
        save_path = Path(args.save).expanduser()
    else:
        save_path = find_save()
        if save_path is None:
            entered = input(
                style("Path to MHP3RD.BIN: ", BOLD)
            ).strip().strip('"')
            if not entered:
                error("No save path given.")
                return 1
            save_path = Path(entered).expanduser()

    if not save_path.is_file():
        error(f"File not found: {display_path(save_path)}")
        return 1

    try:
        payload = decrypt_save(save_path.read_bytes())
    except Exception as exc:
        error(f"Could not read the save: {exc}")
        return 1

    print_header(save_path)
    if args.check:
        print_table(payload)
        print_note()
        print()
        print(style("Read-only mode. No files were written.", GRAY))
        return 0

    interactive_loop(save_path, payload)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        print()
        sys.exit(130)
