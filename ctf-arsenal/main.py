#!/usr/bin/env python3
"""CTF Arsenal: a beginner-friendly, offline CTF helper toolkit."""
import argparse
import base64
import binascii
import hashlib
import string
from pathlib import Path

SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": "PNG image",
    b"\xff\xd8\xff": "JPEG image",
    b"GIF87a": "GIF image",
    b"GIF89a": "GIF image",
    b"%PDF-": "PDF document",
    b"PK\x03\x04": "ZIP archive / DOCX / XLSX / PPTX",
    b"7z\xbc\xaf\x27\x1c": "7-Zip archive",
    b"Rar!\x1a\x07": "RAR archive",
    b"\x1f\x8b": "GZIP archive",
}

def caesar(text: str, shift: int) -> str:
    """Shift ASCII letters; preserve case and all non-letters."""
    result = []
    for char in text:
        if "a" <= char <= "z":
            result.append(chr((ord(char) - 97 + shift) % 26 + 97))
        elif "A" <= char <= "Z":
            result.append(chr((ord(char) - 65 + shift) % 26 + 65))
        else:
            result.append(char)
    return "".join(result)

def caesar_bruteforce(text: str):
    """Return all 26 possible Caesar decodings."""
    return [(shift, caesar(text, -shift)) for shift in range(26)]

def vigenere(text: str, key: str, decrypt: bool = False) -> str:
    """Encrypt/decrypt alphabetic text using a Vigenere key."""
    key_letters = [ord(c.lower()) - 97 for c in key if c.isalpha()]
    if not key_letters:
        raise ValueError("Key must contain at least one alphabetic character.")
    output, index = [], 0
    direction = -1 if decrypt else 1
    for char in text:
        if char.isalpha() and char.isascii():
            base = 65 if char.isupper() else 97
            shift = key_letters[index % len(key_letters)]
            output.append(chr((ord(char) - base + direction * shift) % 26 + base))
            index += 1
        else:
            output.append(char)
    return "".join(output)

def base64_encode(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")

def base64_decode(value: str) -> str:
    try:
        raw = base64.b64decode(value, validate=True)
        return raw.decode("utf-8", errors="replace")
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"Invalid Base64 input: {exc}") from exc

def hex_decode(value: str) -> str:
    try:
        raw = bytes.fromhex(value)
        return raw.decode("utf-8", errors="replace")
    except ValueError as exc:
        raise ValueError(f"Invalid hexadecimal input: {exc}") from exc

def xor_bytes(data: bytes, key: int) -> bytes:
    if not 0 <= key <= 255:
        raise ValueError("XOR key must be between 0 and 255.")
    return bytes(byte ^ key for byte in data)

def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = set(bytes(string.printable, "ascii"))
    return sum(byte in printable for byte in data) / len(data)

def xor_bruteforce(data: bytes, limit: int = 5):
    """Try all single-byte XOR keys; rank results by printable-byte ratio."""
    candidates = []
    for key in range(256):
        decoded = xor_bytes(data, key)
        candidates.append((printable_ratio(decoded), key, decoded))
    return sorted(candidates, reverse=True)[:limit]

def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def inspect_file(path: str) -> dict:
    """Inspect a local file's size, SHA-256, and common magic-byte signature."""
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {path}")
    with file_path.open("rb") as handle:
        header = handle.read(16)
        handle.seek(0)
        digest = hashlib.sha256()
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    file_type = "Unknown / not in built-in signature list"
    for signature, description in SIGNATURES.items():
        if header.startswith(signature):
            file_type = description
            break
    return {"name": file_path.name, "size": file_path.stat().st_size,
            "type": file_type, "sha256": digest.hexdigest(),
            "header_hex": header.hex(" ")}

def build_parser():
    parser = argparse.ArgumentParser(
        prog="ctf-arsenal",
        description="Offline helper utilities for authorized CTF challenges."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("caesar", help="Caesar cipher utilities")
    p.add_argument("action", choices=["encrypt", "decrypt", "bruteforce"])
    p.add_argument("text")
    p.add_argument("--shift", type=int, default=3, help="Shift for encrypt/decrypt (default: 3)")

    p = sub.add_parser("vigenere", help="Vigenere cipher")
    p.add_argument("action", choices=["encrypt", "decrypt"])
    p.add_argument("text")
    p.add_argument("--key", required=True)

    p = sub.add_parser("base64", help="Base64 encode/decode")
    p.add_argument("action", choices=["encode", "decode"])
    p.add_argument("text")

    p = sub.add_parser("hex", help="Decode hexadecimal text")
    p.add_argument("text")

    p = sub.add_parser("xor", help="Single-byte XOR analysis")
    p.add_argument("action", choices=["apply", "bruteforce"])
    p.add_argument("hex_data", help="Input bytes as hexadecimal")
    p.add_argument("--key", type=int, help="Single-byte key (0-255) for apply")

    p = sub.add_parser("hash", help="Calculate SHA-256 of text")
    p.add_argument("text")

    p = sub.add_parser("file", help="Inspect a local file")
    p.add_argument("path")

    return parser

def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == "caesar":
            if args.action == "encrypt":
                print(caesar(args.text, args.shift))
            elif args.action == "decrypt":
                print(caesar(args.text, -args.shift))
            else:
                for shift, candidate in caesar_bruteforce(args.text):
                    print(f"shift={shift:2}: {candidate}")
        elif args.command == "vigenere":
            print(vigenere(args.text, args.key, decrypt=args.action == "decrypt"))
        elif args.command == "base64":
            print(base64_encode(args.text) if args.action == "encode" else base64_decode(args.text))
        elif args.command == "hex":
            print(hex_decode(args.text))
        elif args.command == "xor":
            try:
                data = bytes.fromhex(args.hex_data)
            except ValueError as exc:
                raise ValueError(f"Invalid hexadecimal bytes: {exc}") from exc
            if args.action == "apply":
                if args.key is None:
                    raise ValueError("Use --key for XOR apply.")
                print(xor_bytes(data, args.key).hex(" "))
            else:
                for score, key, decoded in xor_bruteforce(data):
                    print(f"key=0x{key:02x} printable={score:.0%}: {decoded.decode('utf-8', errors='replace')}")
        elif args.command == "hash":
            print(sha256_text(args.text))
        elif args.command == "file":
            info = inspect_file(args.path)
            for key, value in info.items():
                print(f"{key}: {value}")
    except (ValueError, FileNotFoundError) as exc:
        raise SystemExit(f"Error: {exc}") from exc

if __name__ == "__main__":
    main()
