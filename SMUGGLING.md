# Smuggling Extensible Hashes into Existing Software (Without Waiting for Maintainers)

*How users can start carrying canonical, multi-algorithm, permissionlessly
extensible [Hashsets](SPEC.md) inside Zig, Cargo, Nix, Git, URLs, SemVer, and
release notes **today**—without asking upstream maintainers to upgrade or opt
in.*

---

## Why Lowercase Base32 + `-` + `.` Unlocks Everything

Switching digest encoding from Base64 to canonical unpadded lowercase RFC 4648
Base32 (`a`–`z`, `2`–`7`) gives us an extraordinary property: because Base32
contains **zero punctuation**, we can use `-` between the algorithm name and
digest and `.` between entries, restricting the **entire** wire alphabet to
`[a-z0-9-.]`.

Every valid Hashset begins with `[a-z]`, ends with `[a-z2-7]`, and never
contains `..`, `--`, `.-`, or `-.`. As a result, a Hashset string is
*simultaneously*:

- **100% RFC 3986 unreserved** — never percent-encoded in URLs, and never
  mangled in `?query=` parameters or `#fragment`s;
- **Valid SemVer 2.0.0 build metadata** (`1.2.3+<hashset>`);
- **A valid filename on Linux, macOS, and Windows** — case-insensitive
  filesystem safe, never starts with `-` (so never misparsed as a CLI flag),
  never starts or ends with `.` (never a Unix dotfile or invalid Windows
  trailing-dot filename), never contains `/` or `..`;
- **A valid DNS hostname** for up to four 256-bit hashes (each 59-char entry is
  under the 63-char RFC 1035 label limit, and four entries total 239 ≤ 253
  bytes);
- **Safe verbatim** in informal prose, Markdown, Slack/Discord, email, POSIX
  and PowerShell command lines, CSV, JSON, YAML, TOML, and Nix store paths (no
  `+`, `/`, `=`, `_`, `~`, `:`, `,`, `;`, `@`, uppercase, or whitespace).

For example, a single Hashset can carry `blake3`, `sha256`, and a brand-new
algorithm such as `minishake128` ([eprint.iacr.org/2026/2363](https://eprint.iacr.org/2026/2363))
or `sha3-256` side by side:

```text
blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra.sha256-4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq.sha3-256-u774n6f7d3lwmuobi5lkayowml2yb72n4q5ut6uc3afexahyinfa
```

---

## First: The Honest Reality Check on Existing Hash Fields

You **cannot** stuff a Hashset directly *inside* the existing verified hash
field of Zig, Cargo, or Nix without breaking those tools:

- **Zig (`build.zig.zon` `.hash`):** Zig's `src/Package.zig` enforces
  `Package.Hash.max_len == 110` bytes and checks exact byte equality against
  its fixed `$name-$semver-$sha256plus` digest. Putting a Hashset in `.hash`
  breaks `zig build`.
- **Cargo (`Cargo.lock` `checksum`):** Cargo verifies exact 64-character hex
  SHA-256 equality of the `.crate` tarball against `checksum` (and rewrites
  `Cargo.lock` whenever dependencies are resolved).
- **Nix (`hash` / `narHash`):** Nix's `src/libutil/hash.cc` (`Hash::parseSRI` /
  `parseAnyHelper`) strictly parses a single hash from a hardcoded algorithm
  enum (`md5`, `sha1`, `sha256`, `sha512`) and throws `BadHash` on anything
  else—including `blake3`, `minishake128`, or a second hash.

That is inevitable: an existing verifier *must* reject strings that don't match
the single algorithm it knows how to check.

**However**, nearly every real package manager and VCS already has **built-in,
ignored, preserved extension slots**—and because Hashset uses strictly
`[a-z0-9-.]`, users can slip it cleanly into *all* of them today!

---

## Where Users Can Smuggle Hashsets In *Today*

### 1. Zig (`build.zig.zon`) — The Best Hidden Slot of All

In Zig's `src/Package/Manifest.zig`, **both** top-level manifest parsing and
**per-dependency** parsing explicitly contain:

```zig
} else {
    // Ignore unknown fields so that we can add fields in future zig
    // versions without breaking older zig versions.
}
```

That means a Zig user can drop a Hashset **right next to `.hash`** inside
`.dependencies` today, and unmodified `zig build` accepts it with zero errors
and zero warnings:

```zig
.dependencies = .{
    .foo = .{
        .url = "https://example.com/foo-1.0.tar.gz",
        .hash = "foo-1.0.0-...",
        .hashset = "blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra.sha256-4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq",
    },
},
```

A user-run wrapper or CI step reads `build.zig.zon`, verifies `.hashset` under
any reader policy (R1–R7—requiring `blake3`, requiring `minishake128`,
verifying all supported algorithms, etc.), and fails closed on mismatch while
stock `zig build` keeps working untouched.

*(Bonus: for non-git `https://` tarball URLs in Zig, a `#fragment` also passes
through HTTP unmodified. Do not use `#fragment` on `git+https://` URLs in Zig,
because Zig uses `#<oid>` for the Git ref.)*

### 2. Cargo (`Cargo.toml`) — `[workspace.metadata]` & `[package.metadata]` (plus SemVer!)

- **Don't** add custom keys to `Cargo.lock`: Cargo ignores unknown fields on
  read, *but* strips them and drops unused `[metadata]` entries whenever it
  regenerates `Cargo.lock`.
- **Do** put Hashsets in `Cargo.toml` under `[workspace.metadata.*]` or
  `[package.metadata.*]`. Cargo explicitly reserves these tables for user and
  third-party tools, emits zero warnings, preserves them permanently, and even
  exposes them directly as JSON via `cargo metadata --format-version 1`:

  ```toml
  [workspace.metadata.hashset]
  "serde@1.0.210" = "blake3-....sha256-...."
  ```

- **SemVer 2.0.0 build metadata trick:** Because Hashset uses strictly
  `[a-z0-9-.]`, `1.2.3+<hashset>` is **100% valid SemVer 2.0.0**—parsed
  natively by Rust's `semver` crate! (Public registries like crates.io impose
  version-length limits, but git/path/private crates, release tags, and internal
  tooling accept it cleanly.)

### 3. Nix (`*.nix` derivations & `fetchurl`) — `passthru` & URL `#fragment`

- **Don't** add extra keys inside `flake.lock`'s `locked` or `original`
  objects: Nix's `src/libfetchers/fetchers.cc` checks `allowedAttrs` and throws
  an error on unknown attributes, and `nix flake update` regenerates
  `flake.lock`.
- **Do** attach Hashsets via `passthru` (or `meta`) on Nix derivations and
  `fetchurl`:

  ```nix
  src = fetchurl {
    url = "https://example.com/foo-1.0.tar.gz";
    hash = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
    passthru.hashset = "blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra.sha256-4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq";
  };
  ```

  `passthru` does not even change the derivation hash (`drvHash`), survives
  unchanged, and any user tool can inspect `nix eval .#pkg.src.hashset` and
  verify the fetched artifact.

- **URL `#fragment` in `fetchurl`:** `curl` strips `#...` before sending the
  HTTP request, and `[a-z0-9-.]` is even legal inside Nix store path names
  (`[0-9a-zA-Z+-._?=]`), though setting an explicit `name = "foo-1.0.tar.gz"`
  keeps the store path clean.

### 4. Universal Channels (Zero Tool-Specific Coupling)

These work across **every** language, ecosystem, and informal statement right
now:

1. **HTTP release links via URL `#fragment`:**

   ```text
   https://example.com/releases/app-1.2.3.tar.gz#blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra.sha256-4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq
   ```

   Per RFC 3986 §3.5, fragments are client-side only—`curl`, `wget`, browsers,
   Go, Rust, Python, and CDNs strip `#...` before talking to the server. Every
   legacy downloader keeps working, while a Hashset-aware downloader, CI script,
   or browser extension reads `#...` and verifies the downloaded bytes under
   R1–R7!

2. **Git commit & signed-tag trailers (`git interpret-trailers`):**

   ```text
   Release-Hash: blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra.sha256-4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq
   ```

   Ignored by Git, preserved forever across `clone`/`fetch`/`push`, covered
   automatically by GPG/SSH tag signatures (`git tag -s`), and machine-queryable
   via:

   ```sh
   git log -1 --format='%(trailers:key=Release-Hash,valueonly)'
   ```

3. **Filenames, content-addressed object keys, and DNS:**

   Because `[a-z0-9-.]` avoids every filesystem, shell, URL, and DNS hazard, a
   Hashset can literally *be* the filename, S3/GCS object key, or DNS label
   without escaping.

---

## One Crucial Caveat: Know Which Bytes You Are Hashing

When smuggling Hashsets into package managers, be explicit about **what byte
sequence** the digests cover:

- In a **URL `#fragment`**, **Cargo `.crate`**, or **Nix `fetchurl`**, the hash
  unambiguously covers the **raw archive file bytes** (`blake3`, `sha256`,
  `minishake128`, etc.).
- In **Zig `.hash`** (which hashes a canonical filtered directory walk), **Nix
  `narHash`** (which hashes a NAR archive of an unpacked tree), or **Git**
  (which hashes Git tree objects), the native tool hashes a *tree
  serialization*, not a tarball.

If you want to verify an unpacked directory tree rather than a tarball,
Hashset's permissionless algorithm naming handles that cleanly too: define a
tree-serialization-specific algorithm name (such as `nar-blake3`,
`nar-minishake128`, or `zigtar-blake3`) alongside raw-file `blake3` and
`sha256`—no format changes required.
