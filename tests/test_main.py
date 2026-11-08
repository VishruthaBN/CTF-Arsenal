import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from main import (
    caesar, caesar_bruteforce, vigenere, base64_encode, base64_decode,
    hex_decode, xor_bytes, sha256_text, inspect_file
)

class TestCTFArsenal(unittest.TestCase):
    def test_caesar_round_trip(self):
        self.assertEqual(caesar(caesar("Hello, CTF!", 5), -5), "Hello, CTF!")

    def test_caesar_bruteforce_contains_plaintext(self):
        candidates = [text for _, text in caesar_bruteforce("Khoor")]
        self.assertIn("Hello", candidates)

    def test_vigenere_round_trip(self):
        encrypted = vigenere("Attack at Dawn!", "LEMON")
        self.assertEqual(vigenere(encrypted, "LEMON", decrypt=True), "Attack at Dawn!")

    def test_vigenere_rejects_bad_key(self):
        with self.assertRaises(ValueError):
            vigenere("hello", "123")

    def test_base64_round_trip(self):
        self.assertEqual(base64_decode(base64_encode("hello CTF")), "hello CTF")

    def test_hex_decode(self):
        self.assertEqual(hex_decode("43 54 46"), "CTF")

    def test_xor_round_trip(self):
        original = b"flag{test}"
        self.assertEqual(xor_bytes(xor_bytes(original, 42), 42), original)

    def test_sha256_known_value(self):
        self.assertEqual(
            sha256_text("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )

    def test_file_inspection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.png"
            path.write_bytes(b"\x89PNG\r\n\x1a\nsample")
            result = inspect_file(str(path))
            self.assertEqual(result["type"], "PNG image")
            self.assertEqual(result["size"], 14)

if __name__ == "__main__":
    unittest.main()
