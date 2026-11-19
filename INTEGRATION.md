# Embedding Hashset in Existing Tools (Without Maintainer Opt-In)

Hashset is designed first for informal human and release statements ("The
official release has hash `blake3-...`"), and second so **users** can carry
extensible multi-hash verification metadata inside existing ecosystems today
without waiting for upstream maintainers to change their software.

## Reality Check on Existing Verified Hash Fields

Tools that strictly check a single hardcoded hash field (`build.zig.zon`
`.hash`, `Cargo.lock` `checksum`, `flake.lock` `narHash`) reject unknown hash
formats in that field by design. Instead, users can place Hashsets into
**existing extension slots** that those tools already preserve and ignore—and
because Hashset uses strictly `[a-z0-9-.]`, it fits cleanly without quoting or
escaping.

## Ecosystem-by-Ecosystem Guide

### 1. Zig (`build.zig.zon`)

In Zig's `src/Package/Manifest.zig`, both top-level manifest parsing and
per-dependency parsing explicitly ignore unknown struct fields for forward
compatibility. Users can place `.hashset` directly beside `.hash`:

```zig
.dependencies = .{
    .foo = .{
        .url = "https://example.com/foo-1.0.tar.gz",
        .hash = "foo-1.0.0-...",
        .hashset = "blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra.sha256-4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq",
    },
},
```

Unmodified `zig build` accepts this with zero errors or warnings, while a user
wrapper or CI verifier can enforce R1–R7 policies over `.hashset`.

*(Note: For non-git `https://` tarball URLs, a `#fragment` also passes through
HTTP unmodified. Do not put `#fragment` on `git+https://` URLs in Zig, since
Zig uses the URL fragment for the Git commit/ref.)*

### 2. Cargo (`Cargo.toml`)

Do not add extra keys to `Cargo.lock`—Cargo strips unknown lockfile keys on
regeneration. Instead, use Cargo's officially reserved `[workspace.metadata.*]`
or `[package.metadata.*]` tables, which Cargo preserves warning-free and
exposes via `cargo metadata --format-version 1`:

```toml
[workspace.metadata.hashset]
"serde@1.0.210" = "blake3-....sha256-...."
```

Additionally, because Hashset uses strictly `[a-z0-9-.]`, `1.2.3+<hashset>` is
valid SemVer 2.0.0 build metadata (accepted natively by the `semver` crate).

### 3. Nix (`*.nix`, `fetchurl`)

Do not add extra attributes inside `flake.lock`'s `locked`/`original` objects
(`src/libfetchers/fetchers.cc` rejects unknown scheme attributes, and
`nix flake update` rewrites `flake.lock`). Instead, attach Hashsets via
`passthru` (or `meta`) on derivations—`passthru` does not even alter the
derivation hash (`drvHash`):

```nix
src = fetchurl {
  url = "https://example.com/foo-1.0.tar.gz";
  hash = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
  passthru.hashset = "blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra.sha256-4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq";
};
```

URL `#fragments` also work with `fetchurl` (`curl` strips the fragment before
sending the HTTP request; set an explicit `name` if desired).

### 4. Git (Commit Messages & Signed Tags)

Git supports arbitrary RFC 822-style trailers (`git interpret-trailers`) with
zero configuration, preserved across clones/fetches and covered automatically
by signed tags (`git tag -s`):

```text
Release-Hash: blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra.sha256-4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq
```

Query with:

```sh
git log -1 --format='%(trailers:key=Release-Hash,valueonly)'
```

### 5. Universal HTTP Release Links (URL `#fragment`)

```text
https://example.com/releases/app-1.2.3.tar.gz#blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra.sha256-4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq
```

Per RFC 3986 §3.5, fragments are client-side only and never sent to HTTP
servers. Every unmodified downloader (`curl`, `wget`, browsers, CDNs) fetches
the file normally, while a Hashset-aware downloader extracts `#...` and
verifies the downloaded bytes.

### 6. Filenames, Object Keys, and DNS

Because every Hashset is strictly `[a-z0-9-.]`, never starts with `-`, never
starts or ends with `.`, and never contains `..`, it is safe verbatim as a
Windows/macOS/Linux filename, S3/GCS object key, Nix store path component, or
DNS hostname (for up to four 256-bit hashes).

## Hashing Bytes vs. Directory Trees

Always be explicit about **which bytes** a Hashset covers:

- URL `#fragments`, `fetchurl`, and `.crate` tarballs hash the raw archive file
  bytes (`blake3`, `sha256`).
- Directory-tree snapshots (Nix NAR, Zig package trees, Git trees) depend on a
  canonical tree serialization. When hashing a tree format rather than raw file
  bytes, define a distinct algorithm name (for example, `nar-blake3`) so file
  hashes and tree hashes can never be confused.
