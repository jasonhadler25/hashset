---
description: A compact, canonical, permissionlessly extensible multi-hash string format
---

# Hashset

## 1. Introduction

This document specifies **Hashset**, a compact, printable ASCII string format
for carrying one or more cryptographic hash values of a byte sequence.

Hashset is designed for algorithm agility and permissionless extensibility:

* A producer can emit a single digest (e.g., `blake3` only, or `sha256` only),
  multiple digests simultaneously (e.g., both `blake3` and `sha256`), or
  digests from future hash algorithms unknown to older consumers.
* A consumer can require one specific algorithm, prefer a faster or newer
  algorithm with fallback, or verify every supported algorithm present (failing
  if any verified digest mismatches).
* Every valid Hashset uses only lowercase ASCII letters, ASCII digits, `-`, and
  `.`, making it safe in informal prose, URLs, filenames, shells, chat UIs,
  structured configuration files, and SemVer 2.0.0 build metadata without
  quoting or escaping.

Examples (digests of the empty byte string `""`):

    blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra

    sha256-4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq

    blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra.sha256-4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq

    blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra.sha256-4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq.sha3-256-u774n6f7d3lwmuobi5lkayowml2yb72n4q5ut6uc3afexahyinfa

## 2. Conventions Used in This Document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][] ([RFC 2119][],
[RFC 8174][]) when, and only when, they appear in all capitals, as shown here.

`0x` followed by two hexadecimal digits denotes an octet (byte) value in the
0–255 range. `||` denotes byte or string concatenation.

[BCP 14]: https://www.rfc-editor.org/info/bcp14
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119.html
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174.html
[RFC 4648]: https://www.rfc-editor.org/rfc/rfc4648.html
[RFC 5234]: https://www.rfc-editor.org/rfc/rfc5234.html
[BLAKE3]: https://c2sp.org/BLAKE3

### 2.1. Canonical Unpadded Lowercase Base32

The Base32 encoding used throughout is [RFC 4648][], Section 6, converted to
lowercase (`a`–`z` representing values 0–25, `2`–`7` representing values
26–31), with `=` padding omitted.

Encoders MUST generate canonical Base32 per [RFC 4648][], Section 3.5: any
unused trailing bits in the final 5-bit symbol MUST be zero. Decoders MUST
reject:

* empty strings;
* any character outside `a`–`z` (`0x61`–`0x7a`) and `2`–`7` (`0x32`–`0x37`),
  including uppercase letters, `=`, whitespace, and `0`/`1`/`8`/`9`;
* lengths congruent to `1`, `3`, or `6` modulo `8` (which cannot represent an
  integer number of octets);
* any encoding with non-zero trailing bits in the final symbol:
  * `len mod 8 == 2`: final symbol value `v` MUST satisfy `(v & 0x03) == 0`;
  * `len mod 8 == 4`: final symbol value `v` MUST satisfy `(v & 0x0f) == 0`
    (for 32-byte digests, `len == 52`, so the 52nd character is always `a` or `q`);
  * `len mod 8 == 5`: final symbol value `v` MUST satisfy `(v & 0x01) == 0`;
  * `len mod 8 == 7`: final symbol value `v` MUST satisfy `(v & 0x07) == 0`
    (for 64-byte digests, `len == 103`, so the 103rd character is one of
    `a`, `i`, `q`, `y`).

## 3. Wire Format

A Hashset is a non-empty ASCII byte string conforming to the following ABNF
([RFC 5234][]):

    hashset = entry *( "." entry )
    entry   = alg "-" digest
    alg     = lalpha *( lalpha / digit ) *( "-" 1*( lalpha / digit ) )
    digest  = 2*b32char
    lalpha  = %x61-7A              ; 'a'-'z'
    digit   = %x30-39              ; '0'-'9'
    b32char = %x61-7A / %x32-37    ; 'a'-'z', '2'-'7'

In addition to the grammar above, a Hashset MUST satisfy all of the following
canonicality rules:

1. **Strict ascending order & uniqueness:** The `alg` names of consecutive
   entries MUST be strictly increasing in unsigned ASCII bytewise
   lexicographical order (`prev_alg < cur_alg`, where `'-'` (`0x2d`) <
   `'0'`–`'9'` (`0x30`–`0x39`) < `'a'`–`'z'` (`0x61`–`0x7a`)). Duplicate `alg`
   names are therefore forbidden.
2. **Canonical Base32:** Every `digest` MUST decode to a non-empty octet
   sequence under Section 2.1.
3. **No surrounding or embedded whitespace:** Encoders MUST NOT emit and
   decoders MUST NOT trim leading, trailing, or internal whitespace or
   punctuation.

### 3.1. Parsing Procedure

To parse an input string `s`:

1. Reject if `s` is empty or contains any non-ASCII byte.
2. Split `s` on `'.'` (`0x2e`) into one or more entry substrings.
3. Initialize `prev_alg = none`.
4. For each entry substring `e`:
   a. Split `e` on the **last** occurrence of `'-'` (`0x2d`) into `(alg, dig)`.
      Reject if `e` contains no `'-'`.
   b. Reject if `alg` does not match the `alg` ABNF production.
   c. If `prev_alg` is present, reject unless `prev_alg < alg` in ASCII
      bytewise lexicographical order. Set `prev_alg = alg`.
   d. Decode `dig` using canonical unpadded lowercase Base32 (Section 2.1) into
      `raw_bytes`. Reject on any decoding error.
   e. Record `(alg, raw_bytes)`.
5. Return the ordered list of `(alg, raw_bytes)` pairs.

Note: Splitting on the **last** `'-'` is unambiguous because `digest` never
contains `'-'`. Even an erroneous parser that splits on the first `'-'` fails
closed on hyphenated algorithm names (such as `sha3-256`) because the remaining
`'-'` is rejected by the Base32 decoder.

### 3.2. Encoding Procedure

To encode a non-empty map from valid `alg` names to non-empty raw digest byte
sequences:

1. Validate every `alg` against the `alg` ABNF and verify every digest is
   non-empty.
2. Sort entries strictly by `alg` in ascending ASCII bytewise order.
3. Encode each entry as `alg || "-" || base32(digest)`.
4. Join the encoded entries with `"."`.

### 3.3. Resulting Character-Set Invariants

Every valid Hashset consists solely of `[a-z0-9-.]`, starts with `[a-z]`, ends
with `[a-z2-7]`, and never contains `..`, `--`, `.-`, or `-.`. Therefore it
cannot be interpreted as a CLI option flag, a hidden dotfile, a Windows
trailing-dot filename, a path traversal, a Markdown formatting token, or a
percent-encoded URL component.

## 4. Algorithm Names and Permissionless Extensibility

A Hashset does not encode a separate digest length field or inline parameter
list. Instead, each algorithm name uniquely defines:

* the exact cryptographic hash function,
* its mode and any domain separation or personalization, and
* its exact fixed output byte length.

### 4.1. Initial Defined Algorithms

| Name     | Specification                                            | Output Length | Base32 Length |
|----------|----------------------------------------------------------|--------------:|--------------:|
| `blake3` | [BLAKE3][] unkeyed `hash` mode (standard 256-bit output) | 32 bytes      | 52 chars      |
| `sha256` | SHA-256 (FIPS 180-4, 256-bit output)                     | 32 bytes      | 52 chars      |

`blake3` uses BLAKE3's standard 256-bit (32-byte) output length; per the BLAKE3
specification, general-purpose hashing should not use non-256-bit output
lengths.

### 4.2. Adding New Algorithms Without Permission

Any community or implementer MAY define new algorithm names without central
coordination, provided:

1. The name conforms to the `alg` ABNF (`[a-z][a-z0-9]*(-[a-z0-9]+)*`).
2. The name unambiguously identifies a single algorithm, mode, and fixed output
   length. Distinct algorithms or output lengths require distinct names (for
   example, `sha512` for 512-bit SHA-2, or `sha3-256` and `sha3-512` for SHA-3).
3. To avoid collisions between independent adopters, well-known standardized
   algorithms SHOULD use their common lowercase name (including bit-length when
   the family has variants, e.g., `sha3-256`, `sha512`, `blake2b-256`), and
   experimental or organization-specific algorithms SHOULD use an owner prefix
   such as `x-<owner>-<name>` (e.g., `x-acme-myhash`).

Readers MUST NOT reject a Hashset solely because it contains an unrecognized
`alg` name, provided the unknown entry is syntactically valid per Section 3.1
(including arbitrary non-empty digest byte length).

## 5. Verification Semantics and Reader Policies

Verification is strictly a two-phase process:

1. **Full syntactic validation:** A reader MUST parse and validate the entire
   Hashset string per Section 3.1 *before* making any trust decision. Any
   syntax error, ordering violation, duplicate tag, or non-canonical Base32
   encoding—even inside a skipped or unrecognized entry—MUST cause immediate
   rejection.
2. **Policy selection and verification:** The reader selects a non-empty subset
   of entries to verify, computes each selected algorithm over the target byte
   sequence, and compares each computed digest against the decoded entry bytes
   for exact length and constant-time equality.
   * If **no** supported entry is selected, verification MUST fail (fail closed).
   * If **any** selected entry fails to match, verification MUST fail.
   * Unselected entries (whether unrecognized or intentionally skipped by
     policy) are ignored after Phase 1.

Two standard policies cover all common readers:

* **Priority-fallback (`verify_first(priority)`):** Given an ordered list of
  preferred algorithm names `priority`, select the first algorithm in
  `priority` present in the Hashset and verify it.
  * **R1** (`sha256` only): `priority = ["sha256"]`
  * **R2** (`blake3` only): `priority = ["blake3"]`
  * **R3** (`blake3`, else `sha256`): `priority = ["blake3", "sha256"]`
  * **R5** (require `new1`): `priority = ["new1"]`
  * **R6** (`new1`, fallback): `priority = ["new1", "blake3", "sha256"]`
* **Verify-all-supported (`verify_all(supported)`):** Given a set of supported
  algorithm names `supported`, select **every** entry in the Hashset whose
  `alg` is in `supported` (ignoring any unknown entries not in `supported`).
  Fail if none are selected or if **any** selected entry fails to verify.
  * **R4** (both `blake3` and `sha256` if present): `supported = {"blake3", "sha256"}`
  * **R7** (all of `blake3`, `sha256`, `new1` present): `supported = {"blake3", "sha256", "new1"}`

Because Phase 1 completes before hashing begins, `verify_all` readers can
stream large inputs in a single pass while feeding all selected hashers in
parallel.

## 6. Security and Implementation Considerations

* **Canonicality and non-malleability:** Rejecting non-zero trailing Base32
  bits, uppercase letters, whitespace, and unsorted entries ensures every
  logical set of `(alg, digest)` pairs has a unique wire representation.
  Hashset equality is therefore exact byte-string equality.
* **No silent partial-parse acceptance:** Never stop scanning a Hashset early
  upon seeing a preferred algorithm (such as `blake3` in R3). Always parse the
  entire string first so malformed tails or duplicate tags cannot cause
  disagreement between R3 and R4 readers.
* **Authentication of the Hashset itself:** A Hashset provides data integrity
  only when the Hashset string is obtained from a trusted or authenticated
  channel (e.g., signed release notes, signed Git tag, HTTPS, or versioned
  lockfile). If an adversary can modify an unauthenticated Hashset in transit,
  they could strip a stronger algorithm when talking to a fallback reader (R3
  or R6); readers that must not fall back SHOULD use R5 or omit weaker
  algorithms from their policy.
* **Prose boundaries:** When a Hashset appears at the end of an English
  sentence (`...this hash: blake3-v4ju...gjra.`), accidental inclusion of the
  trailing sentence period is rejected cleanly by the parser rather than
  misparsed.
* **Resource limits:** Implementations MAY enforce a maximum input length or
  entry count to prevent denial of service, but SHOULD accept at least 4096
  bytes and 32 entries so older readers continue to accept future multi-hash
  Hashsets containing larger digests (e.g., 64-byte SHA-512 digests).
* **Domain of the hash:** Hashset encodes digests of a byte sequence. When
  hashing structured objects (such as directory trees or archives), the
  enclosing context—or a dedicated algorithm name such as `nar-blake3`—MUST
  define the canonical serialization to bytes.

## Appendix A: Test Vectors

### A.1. Valid Vectors

Input `""` (empty byte string):
* `blake3` (hex, 32 B): `af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262`
* `sha256` (hex, 32 B): `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
* `sha3-256` (hex, 32 B): `a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a`
* `sha512` (hex, 64 B): `cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e`

```text
W1 (59 B):  blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra
W2 (59 B):  sha256-4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq
W3 (119 B): blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra.sha256-4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq
W4 (181 B): blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra.sha256-4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq.sha3-256-u774n6f7d3lwmuobi5lkayowml2yb72n4q5ut6uc3afexahyinfa
W5 (230 B): blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra.sha256-4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq.sha512-z6b6cnl6564l34kufbinm3maa7lcbzafbnlrlxed6susdu3m5hhepugrhroyl4vq76brruuhp3wc6y5zgg6uoql2qgstqmt27et5upq
```

Input `"abc"` (`0x61 0x62 0x63`):
* `blake3` (hex, 32 B): `6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85`
* `sha256` (hex, 32 B): `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`

```text
W3 (119 B): blake3-mq33hlbyizith75whn2soounwvemkwcglv45wa75gwogzvn5twcq.sha256-xj4bnp4pahh6uqkbidpf3lrceoyagyndsylxvhfucd7wd4qacwwq
```

Input `"hello\n"` (`0x68 0x65 0x6c 0x6c 0x6f 0x0a`):
* `blake3` (hex, 32 B): `8e4c7c1b99dbfd50e7a95185fead5ee1448fa904a2fdd778eaf5f2dbfd629a99`
* `sha256` (hex, 32 B): `5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03`

```text
W3 (119 B): blake3-rzghyg4z3p6vbz5jkgc75lk64fci7kieul65o6hk6xznx7lctkmq.sha256-lci3lnjc2xpqq3ip6cyrb66z2in3j7drmoxtjuecq2roqrxwxybq
```

### A.2. Invalid Vectors (Decoders MUST Reject)

| Input | Reason |
|---|---|
| `""` | Empty string |
| `BLAKE3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra` | Uppercase algorithm name |
| `blake3-V4JUTOPV7GQ2NICAJXVDNXGJJGN4WJOJVXARFN6MTKJ4VZA7GJRA` | Uppercase Base32 |
| `blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra====` | Base32 `=` padding |
| `blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjrb` | Non-canonical trailing bits (32 B: `a`→`b`) |
| `sha512-z6b6cnl6564l34kufbinm3maa7lcbzafbnlrlxed6susdu3m5hhepugrhroyl4vq76brruuhp3wc6y5zgg6uoql2qgstqmt27et5upr` | Non-canonical trailing bits (64 B: `q`→`r`) |
| `sha256-4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq.blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra` | Unsorted (`sha256 > blake3`) |
| `blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra.blake3-mq33hlbyizith75whn2soounwvemkwcglv45wa75gwogzvn5twcq` | Duplicate algorithm |
| `blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra.` | Trailing `.` (prose period) |
| `.blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra` | Leading `.` |
| `blake3--v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra` | Consecutive `--` / trailing `-` in `alg` |
| `-blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra` | Leading `-` |
| `3blake-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra` | `alg` starts with digit |
| `blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjr0` | Invalid Base32 char `'0'` |
| `blake3-a` | Impossible Base32 length (`1 mod 8`) |
| `blake3-aaa` | Impossible Base32 length (`3 mod 8`) |
| `blake3-` | Empty digest |
| `blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra ` | Trailing space |
