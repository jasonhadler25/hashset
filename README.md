# Hashset

A compact, canonical, permissionlessly extensible ASCII format for carrying one
or more cryptographic hash values.

```text
# BLAKE3 only (59 chars)
blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra

# SHA-256 only (59 chars)
sha256-4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq

# Both BLAKE3 and SHA-256 (119 chars)
blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra.sha256-4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq

# Forward-compatible with future algorithms (e.g., SHA3-256)
blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra.sha256-4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq.sha3-256-u774n6f7d3lwmuobi5lkayowml2yb72n4q5ut6uc3afexahyinfa
```

## Key Properties

- **UI- and parser-safe alphabet:** Uses strictly `[a-z0-9-.]` (canonical
  unpadded lowercase RFC 4648 Base32 digests, `-` between algorithm and digest,
  `.` between entries). Safe without escaping in prose, Markdown, chat UIs,
  URLs (100% RFC 3986 unreserved), Windows/macOS/Linux filenames, shells, CSV,
  JSON, YAML, TOML, SemVer 2.0.0 build metadata, and DNS hostnames.
- **Canonical and unambiguous:** One wire representation per set of digests
  (strict ascending ASCII order by algorithm name, no duplicates, no whitespace,
  no padding, strict zero trailing Base32 bits per RFC 4648 §3.5).
- **Permissionless extensibility:** Variable-length algorithm names (`blake3`,
  `sha256`, `sha3-256`, `sha512`, `x-<org>-<alg>`, …) with no central numeric
  registry and no fixed digest length in the parser.
- **Flexible, fail-closed reader policies:** Supports single-algorithm readers
  (R1, R2, R5), priority-fallback readers (R3, R6), and verify-all-supported
  readers (R4, R7 — failing if *any* checked digest mismatches).

## Repository Contents

- [`SPEC.md`](SPEC.md) — Normative English specification (C2SP style) with valid
  and invalid test vectors.
- [`Hashset.lean`](Hashset.lean) — Self-contained executable formal
  specification and verification properties in Lean 4.
- [`INTEGRATION.md`](INTEGRATION.md) — Practical guide to embedding Hashsets in
  existing tools (Zig, Cargo, Nix, Git, URLs, SemVer) without waiting for
  upstream maintainer changes.
- [`reference/hashset.py`](reference/hashset.py) — Zero-dependency Python 3
  reference implementation.
- [`reference/test_hashset.py`](reference/test_hashset.py) — Test suite covering
  all specification vectors, reader policies R1–R7, and round-trip/canonicality
  checks.

## Running the Reference Tests

```sh
python3 -m unittest discover -s reference -v
```
