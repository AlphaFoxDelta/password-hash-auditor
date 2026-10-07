#!/usr/bin/env python3
"""
Dictionary-attack auditor for SHA-256 hashes. Defensive tool.

Crack your own weak passwords before someone else does — the demo is meant
to make the case for MFA and a real password policy. Only audit hashes you
own or are allowed to test.

Stdlib only.
"""

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_WORDLIST = SCRIPT_DIR / "wordlist.txt"

# the usual leet substitutions
LEET = {
    "a": "@", "e": "3", "i": "1", "o": "0", "s": "$",
    "t": "7", "l": "1", "g": "9", "b": "8",
}

# digits and years people tack onto passwords
SUFFIXES = ["", "1", "12", "123", "1234", "12345", "0", "00", "01", "2", "3",
            "7", "69", "99", "007", "111", "666"]
SUFFIXES += [str(year) for year in range(1990, 2027)]


def case_variants(word):
    """password, Password, PASSWORD, pASSWORD..."""
    variants = {word, word.lower(), word.upper(), word.capitalize()}
    if word:
        variants.add(word[0].swapcase() + word[1:])
    return variants


def leet_variants(word):
    """Full leet plus one-substitution-at-a-time."""
    variants = {"".join(LEET.get(c, c) for c in word)}
    for i, char in enumerate(word):
        if char in LEET:
            variants.add(word[:i] + LEET[char] + word[i + 1:])
    return variants


def mutate(word):
    """Every candidate from one word. Deduped."""
    seen = set()
    bases = set()
    bases.update(case_variants(word))
    for base in (word.lower(), word.capitalize()):
        bases.update(leet_variants(base))
    for base in bases:
        for suffix in SUFFIXES:
            candidate = base + suffix
            if candidate not in seen:
                seen.add(candidate)
                yield candidate


def load_wordlist(path):
    """One base word per line. Skip blanks and comments."""
    words = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            word = line.strip()
            if word and not word.startswith("#"):
                words.append(word)
    if not words:
        raise ValueError(f"wordlist is empty: {path}")
    return words


def load_hashes(path):
    """One hash per line: '<sha256>' or '<label>:<sha256>'."""
    entries = []  # list of (label, hexdigest)
    with open(path, encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                label, _, digest = line.partition(":")
                label, digest = label.strip(), digest.strip().lower()
            else:
                label, digest = f"hash-{lineno}", line.lower()
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                print(f"warning: skipping invalid SHA-256 on line {lineno}",
                      file=sys.stderr)
                continue
            entries.append((label, digest))
    if not entries:
        raise ValueError(f"no valid SHA-256 hashes found in: {path}")
    return entries


def crack(entries, wordlist):
    """Run the dictionary attack. Returns (cracked, guesses, seconds).

    cracked maps hash -> (label, password), in crack order.
    """
    remaining = {digest: label for label, digest in entries}
    cracked = {}
    guesses = 0
    start = time.perf_counter()
    for word in wordlist:
        for candidate in mutate(word):
            guesses += 1
            digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
            if digest in remaining:
                cracked[digest] = (remaining.pop(digest), candidate)
                if not remaining:
                    break
        if not remaining:
            break
    elapsed = time.perf_counter() - start
    return cracked, guesses, elapsed


def run_benchmark(wordlist, target=200_000):
    """Raw hashing speed. No hash file needed."""
    candidates = []
    for word in wordlist:
        candidates.extend(mutate(word))
        if len(candidates) >= target:
            break
    candidates = candidates[:target]
    start = time.perf_counter()
    for candidate in candidates:
        hashlib.sha256(candidate.encode("utf-8")).hexdigest()
    elapsed = time.perf_counter() - start
    return len(candidates), elapsed


def short(digest):
    return digest[:12] + "..."


def print_report(entries, cracked, guesses, elapsed, hashes_path, wordlist_path,
                 word_count):
    total = len(entries)
    found = len(cracked)
    rate = guesses / elapsed if elapsed > 0 else 0.0
    print("Password Hash Auditor -- SHA-256 dictionary audit")
    print("=" * 55)
    print(f"Hashes file : {hashes_path} ({total} hashes)")
    print(f"Wordlist    : {wordlist_path} ({word_count} words)")
    print()
    for digest, (label, password) in cracked.items():
        print(f"[CRACKED] {label} ({short(digest)}) -> {password}")
    for label, digest in entries:
        if digest not in cracked:
            print(f"[--------] {label} ({short(digest)}) -> not cracked")
    print()
    print(f"Summary: cracked {found}/{total} hashes")
    print(f"Guesses attempted : {guesses:,}")
    print(f"Time taken        : {elapsed:.2f} s")
    print(f"Rate              : {rate:,.0f} guesses/sec")


def print_json(entries, cracked, guesses, elapsed):
    payload = {
        "cracked": [
            {"label": label, "hash": digest, "password": password}
            for digest, (label, password) in cracked.items()
        ],
        "uncracked": [
            {"label": label, "hash": digest}
            for label, digest in entries if digest not in cracked
        ],
        "stats": {
            "hashes": len(entries),
            "cracked": len(cracked),
            "guesses": guesses,
            "seconds": round(elapsed, 3),
            "guesses_per_second": round(guesses / elapsed, 1) if elapsed > 0 else 0.0,
        },
    }
    print(json.dumps(payload, indent=2))


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Defensive SHA-256 password hash auditor. "
                    "Only audit hashes you own or are authorized to test.")
    parser.add_argument("hashes", nargs="?",
                        help="file with one SHA-256 hash per line "
                             "('<hash>' or '<label>:<hash>')")
    parser.add_argument("--wordlist", default=str(DEFAULT_WORDLIST),
                        help="dictionary file, one base word per line "
                             f"(default: {DEFAULT_WORDLIST.name})")
    parser.add_argument("--json", action="store_true",
                        help="emit machine-readable JSON instead of text")
    parser.add_argument("--benchmark", action="store_true",
                        help="measure hashing throughput (guesses/sec); "
                             "runs standalone when no hashes file is given")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    try:
        wordlist = load_wordlist(args.wordlist)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # benchmark without a hash file
    if args.benchmark and not args.hashes:
        count, elapsed = run_benchmark(wordlist)
        rate = count / elapsed if elapsed > 0 else 0.0
        if args.json:
            print(json.dumps({
                "benchmark": True,
                "guesses": count,
                "seconds": round(elapsed, 3),
                "guesses_per_second": round(rate, 1),
            }, indent=2))
        else:
            print(f"Benchmark: {count:,} guesses in {elapsed:.2f} s "
                  f"-> {rate:,.0f} guesses/sec")
        return 0

    if not args.hashes:
        print("error: a hashes file is required (unless using --benchmark "
              "standalone)", file=sys.stderr)
        return 2

    try:
        entries = load_hashes(args.hashes)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    cracked, guesses, elapsed = crack(entries, wordlist)

    if args.json:
        print_json(entries, cracked, guesses, elapsed)
    else:
        print_report(entries, cracked, guesses, elapsed,
                     args.hashes, args.wordlist, len(wordlist))

    if args.benchmark and not args.json:
        rate = guesses / elapsed if elapsed > 0 else 0.0
        print(f"(benchmark) {rate:,.0f} guesses/sec over this audit")
    return 0


if __name__ == "__main__":
    sys.exit(main())
