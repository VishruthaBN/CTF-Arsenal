# CTF Arsenal 

A beginner-friendly, offline Python toolkit for common **authorized Capture The Flag (CTF)** tasks. It brings together classical cipher utilities, encoding/decoding helpers, single-byte XOR analysis, hashing, and basic file-signature inspection.

> **Learning project:** Built to understand common CTF concepts. It is not a replacement for dedicated forensic tools, and its heuristics can produce false positives.

## Features

| Module | Capabilities |
|---|---|
| Caesar | Encrypt, decrypt, try all 26 shifts |
| Vigenère | Encrypt and decrypt using a keyword |
| Encoding | Base64 encode/decode and hexadecimal decoding |
| XOR | Apply a single-byte XOR key and rank brute-force candidates |
| Hashing | Calculate SHA-256 hashes of text |
| File inspection | Report file size, SHA-256, first bytes, and common magic-byte signatures |

## Requirements

- Python 3.9 or newer
- No third-party dependencies (Python standard library only)

## Setup

```bash
git clone https://github.com/VishruthaBN/CTF-Arsenal.git
cd CTF-Arsenal
python main.py --help
```

On Windows, use `py` instead of `python` if that is how Python is configured.

## Usage examples

```bash
# Caesar cipher
python main.py caesar encrypt "hello world" --shift 3
python main.py caesar decrypt "khoor zruog" --shift 3
python main.py caesar bruteforce "khoor zruog"

# Vigenere cipher
python main.py vigenere encrypt "Attack at Dawn" --key LEMON
python main.py vigenere decrypt "Lxfopv ef Rnhr" --key LEMON

# Encodings
python main.py base64 encode "hello CTF"
python main.py base64 decode "aGVsbG8gQ1RG"
python main.py hex "43 54 46"

# Single-byte XOR (input is hexadecimal)
python main.py xor apply "68656c6c6f" --key 42
python main.py xor bruteforce "2a2f262626"

# SHA-256
python main.py hash "hello"

# Local file inspection
python main.py file sample.png
```

## Run tests

```bash
python -m unittest discover -s tests -v
```

## Project structure

```text
CTF-Arsenal/
├── main.py
├── tests/
│   └── test_main.py
├── README.md
├── requirements.txt
└── LICENSE
```

## Concepts demonstrated

- Modular Python functions and command-line argument parsing
- Caesar and Vigenère substitution ciphers
- Base64 and hexadecimal representation
- XOR operations and brute-force search
- SHA-256 hashing
- File magic bytes and basic file identification
- Unit testing with `unittest`

## Limitations

- Caesar brute-force lists all shifts; it does not automatically decide which plaintext is correct.
- Single-byte XOR ranking uses printable-character ratio, which is only a simple heuristic.
- File identification checks a small set of signatures and is not comprehensive.
- SHA-256 is a hash function, not encryption; it cannot be reversed.

## Responsible use

Use this toolkit only on data and files you own or are explicitly authorized to analyze, such as practice CTF challenge artifacts.

## Credits

Implemented as an educational project using Python's standard library. No external source code is copied into this repository.
