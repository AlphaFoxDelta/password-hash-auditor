#!/usr/bin/env python3
"""
Generates hashes.txt for the demo: five weak passwords, one strong one.

Only hashes get written — the plaintexts are in the README.
"""

import hashlib
from pathlib import Path

# frank's password isn't in the wordlist. it shouldn't crack.
SAMPLES = [
    ("alice", "password"),             # dictionary word, as-is
    ("bob", "Password123"),            # capitalization + digits
    ("carol", "qwerty"),               # common / keyboard pattern
    ("dave", "letmein2024"),           # word + year
    ("erin", "P@ssw0rd"),              # leet-speak
    ("frank", "Tr7$kQ!9zX2#bW8@mN"),   # strong: 16 chars, all classes
]


def main():
    out_path = Path(__file__).resolve().parent / "hashes.txt"
    with open(out_path, "w", encoding="utf-8") as handle:
        for label, plaintext in SAMPLES:
            digest = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
            handle.write(f"{label}:{digest}\n")
    print(f"Wrote {len(SAMPLES)} sample hashes to {out_path}")


if __name__ == "__main__":
    main()
