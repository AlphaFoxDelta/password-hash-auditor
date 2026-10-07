# password-hash-auditor

A dictionary-attack auditor for SHA-256 password hashes. Feed it a hash
list, it tries the mutations real attackers try first, and it tells you,
usually in under a second, which passwords were a bad idea. Standard
library only.

## Why I built this

I wanted a defensive project with a punchline you can demo in an
interview: run it, watch five passwords fall in 0.03 seconds, and there's
your argument for MFA and a real password policy. Nobody argues with a
live crack.

It's also the flip side of my offensive projects. Same technique
(dictionary attack), opposite intent: auditing your own hashes instead of
someone else's.

## What it does

- For each wordlist entry, generates candidates the way attackers do:
  case variations (`password`, `Password`, `PASSWORD`), leet-speak
  (`p@ssw0rd`, plus one-substitution-at-a-time), and appended digits/years
  (`Password123`, `letmein2024`)
- SHA-256 hashes each candidate and compares against the target list
- Stops early once everything's cracked
- `--benchmark` mode measures raw hashing throughput (guesses/sec)
- `--json` for machine-readable output

## Quick start

No dependencies. Python 3.8+ is all you need.

```bash
# 1. generate the demo hashes (5 weak + 1 strong)
python3 make_sample_hashes.py

# 2. run the audit
python3 auditor.py hashes.txt
```

Sample output:

```
Password Hash Auditor -- SHA-256 dictionary audit
=======================================================
Hashes file : hashes.txt (6 hashes)
Wordlist    : /path/to/wordlist.txt (45 words)

[CRACKED] alice (5e884898da28...) -> password
[CRACKED] bob (008c70392e3a...) -> Password123
[CRACKED] carol (65e84be33532...) -> qwerty
[CRACKED] dave (2ad48f9069e9...) -> letmein2024
[CRACKED] erin (b03ddf3ca2e7...) -> P@ssw0rd
[--------] frank (3942b774accf...) -> not cracked

Summary: cracked 5/6 hashes
Guesses attempted : 24,084
Time taken        : 0.03 s
Rate              : 820,024 guesses/sec
```

Five weak passwords fall in 0.03 seconds. The 16-character mixed password
survives. Length wins.

## CLI reference

```bash
python3 auditor.py hashes.txt [options]

positional:
  hashes               file with one SHA-256 hash per line,
                       as "<hash>" or "<label>:<hash>"

options:
  --wordlist FILE      dictionary file, one base word per line
                       (default: bundled wordlist.txt)
  --json               emit machine-readable JSON instead of text
  --benchmark          report guesses/sec; runs standalone
                       (no hashes file needed) to measure raw
                       hashing throughput
```

JSON output:

```bash
python3 auditor.py hashes.txt --json
```

```json
{
  "cracked": [
    {"label": "alice", "hash": "5e8848...", "password": "password"}
  ],
  "uncracked": [
    {"label": "frank", "hash": "3942b7..."}
  ],
  "stats": {
    "hashes": 6,
    "cracked": 5,
    "guesses": 24084,
    "seconds": 0.03,
    "guesses_per_second": 820024.0
  }
}
```

Benchmark mode:

```bash
$ python3 auditor.py --benchmark
Benchmark: 24,084 guesses in 0.02 s -> 1,510,696 guesses/sec
```

## What tripped me up

Deduplication. My first version generated the same candidate a dozen
different ways (case variants overlapping with leet variants and so on),
and the guess count was inflated with repeats. The audit still "worked,"
it was just doing a bunch of wasted hashes. A `seen` set fixed it, but it
took me a while to notice. The benchmark numbers looking oddly low is what
tipped me off.

Also: years. I generate suffixes for every year from 1990 to 2026, which
felt like overkill until I remembered how many passwords end in a year.

## What I'd do differently

- This targets fast unsalted SHA-256, which is the easy case. Real
  systems should be on bcrypt, scrypt, or Argon2: memory-hard hashes
  that make this kind of volume impractical. That's kind of the point of
  the demo, but supporting those hashes would make the tool honest about
  modern password storage.
- The mutation set is deliberately bounded. A real attacker with hashcat
  and GPUs tries far more. Multiprocessing would be the next step if I
  wanted speed.
- A rules engine (hashcat-style) instead of hardcoded mutations.

## A note on using this

Only audit hashes you own or are explicitly authorized to test. Running
this against someone else's credentials is unauthorized access in most
places. This exists to help defenders: strengthen policy, justify MFA,
educate users.
