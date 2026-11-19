"""Test suite for the Hashset reference implementation (SPEC.md Appendix A + R1-R7)."""

import base64
import hashlib
import os
import struct
import unittest

import hashset as hs


# Minimal single-block BLAKE3 (messages <= 64 bytes) for zero-dependency vector testing.
_IV = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)
_PERM = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)


def _rotr32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def _blake3_short(data: bytes) -> bytes:
    assert len(data) <= 64
    m = list(struct.unpack("<16I", data + b"\x00" * (64 - len(data))))
    s = list(_IV) + list(_IV[:4]) + [0, 0, len(data), 1 | 2 | 8]

    def g(a: int, b: int, c: int, d: int, mx: int, my: int) -> None:
        s[a] = (s[a] + s[b] + mx) & 0xFFFFFFFF
        s[d] = _rotr32(s[d] ^ s[a], 16)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF
        s[b] = _rotr32(s[b] ^ s[c], 12)
        s[a] = (s[a] + s[b] + my) & 0xFFFFFFFF
        s[d] = _rotr32(s[d] ^ s[a], 8)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF
        s[b] = _rotr32(s[b] ^ s[c], 7)

    for _ in range(7):
        g(0, 4, 8, 12, m[0], m[1])
        g(1, 5, 9, 13, m[2], m[3])
        g(2, 6, 10, 14, m[4], m[5])
        g(3, 7, 11, 15, m[6], m[7])
        g(0, 5, 10, 15, m[8], m[9])
        g(1, 6, 11, 12, m[10], m[11])
        g(2, 7, 8, 13, m[12], m[13])
        g(3, 4, 9, 14, m[14], m[15])
        m = [m[i] for i in _PERM]
    return struct.pack("<8I", *(s[i] ^ s[i + 8] for i in range(8)))


HASHERS = {
    "blake3": _blake3_short,
    "sha256": lambda b: hashlib.sha256(b).digest(),
    "sha3-256": lambda b: hashlib.sha3_256(b).digest(),
    "sha512": lambda b: hashlib.sha512(b).digest(),
}


class TestBase32(unittest.TestCase):
    def test_roundtrip_and_stdlib_agreement(self) -> None:
        for length in range(1, 66):
            raw = os.urandom(length)
            ref = base64.b32encode(raw).rstrip(b"=").decode("ascii").lower()
            enc = hs.b32_encode(raw)
            self.assertEqual(enc, ref)
            self.assertEqual(hs.b32_decode(enc), raw)

    def test_reject_non_canonical_trailing_bits(self) -> None:
        for length, mask in [(1, 0x03), (2, 0x0F), (3, 0x01), (4, 0x07), (32, 0x0F), (64, 0x07)]:
            raw = os.urandom(length)
            enc = hs.b32_encode(raw)
            last_v = hs._b32_decode_char(enc[-1])
            for delta in range(1, mask + 1):
                bad = enc[:-1] + hs._b32_encode_digit(last_v | delta)
                with self.assertRaises(hs.HashsetError):
                    hs.b32_decode(bad)


class TestVectors(unittest.TestCase):
    def test_valid_appendix_a1(self) -> None:
        w1 = "blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra"
        w2 = "sha256-4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq"
        w3 = f"{w1}.{w2}"
        w4 = f"{w3}.sha3-256-u774n6f7d3lwmuobi5lkayowml2yb72n4q5ut6uc3afexahyinfa"
        w5 = f"{w3}.sha512-z6b6cnl6564l34kufbinm3maa7lcbzafbnlrlxed6susdu3m5hhepugrhroyl4vq76brruuhp3wc6y5zgg6uoql2qgstqmt27et5upq"

        self.assertEqual(hs.format_hashset({"blake3": HASHERS["blake3"](b"")}), w1)
        self.assertEqual(hs.format_hashset({"sha256": HASHERS["sha256"](b"")}), w2)
        self.assertEqual(
            hs.format_hashset({"sha256": HASHERS["sha256"](b""), "blake3": HASHERS["blake3"](b"")}),
            w3,
        )
        self.assertEqual(
            hs.format_hashset({
                "sha3-256": HASHERS["sha3-256"](b""),
                "sha256": HASHERS["sha256"](b""),
                "blake3": HASHERS["blake3"](b""),
            }),
            w4,
        )
        self.assertEqual(
            hs.format_hashset({
                "sha512": HASHERS["sha512"](b""),
                "sha256": HASHERS["sha256"](b""),
                "blake3": HASHERS["blake3"](b""),
            }),
            w5,
        )
        for vec in (w1, w2, w3, w4, w5):
            parsed = hs.parse_hashset(vec)
            self.assertEqual(hs.format_hashset(parsed), vec)

        abc_w3 = (
            "blake3-mq33hlbyizith75whn2soounwvemkwcglv45wa75gwogzvn5twcq."
            "sha256-xj4bnp4pahh6uqkbidpf3lrceoyagyndsylxvhfucd7wd4qacwwq"
        )
        self.assertEqual(
            hs.format_hashset({"blake3": HASHERS["blake3"](b"abc"), "sha256": HASHERS["sha256"](b"abc")}),
            abc_w3,
        )

        hello_w3 = (
            "blake3-rzghyg4z3p6vbz5jkgc75lk64fci7kieul65o6hk6xznx7lctkmq."
            "sha256-lci3lnjc2xpqq3ip6cyrb66z2in3j7drmoxtjuecq2roqrxwxybq"
        )
        self.assertEqual(
            hs.format_hashset({"blake3": HASHERS["blake3"](b"hello\n"), "sha256": HASHERS["sha256"](b"hello\n")}),
            hello_w3,
        )

    def test_invalid_appendix_a2(self) -> None:
        invalid = [
            "",
            "BLAKE3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra",
            "blake3-V4JUTOPV7GQ2NICAJXVDNXGJJGN4WJOJVXARFN6MTKJ4VZA7GJRA",
            "blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra====",
            "blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjrb",
            "sha512-z6b6cnl6564l34kufbinm3maa7lcbzafbnlrlxed6susdu3m5hhepugrhroyl4vq76brruuhp3wc6y5zgg6uoql2qgstqmt27et5upr",
            "sha256-4oymiquy7qobjgx36tejs35zeqt24qpemsnzgtfeswmrw6csxbkq.blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra",
            "blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra.blake3-mq33hlbyizith75whn2soounwvemkwcglv45wa75gwogzvn5twcq",
            "blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra.",
            ".blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra",
            "blake3--v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra",
            "-blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra",
            "3blake-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra",
            "blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjr0",
            "blake3-a",
            "blake3-aaa",
            "blake3-",
            "blake3-v4jutopv7gq2nicajxvdnxgjjgn4wjojvxarfn6mtkj4vza7gjra ",
        ]
        for bad in invalid:
            with self.subTest(bad=bad):
                with self.assertRaises(hs.HashsetError):
                    hs.parse_hashset(bad)


class TestReaderPolicies(unittest.TestCase):
    def setUp(self) -> None:
        self.msg = b"abc"
        self.b3 = HASHERS["blake3"](self.msg)
        self.s2 = HASHERS["sha256"](self.msg)
        self.s3 = HASHERS["sha3-256"](self.msg)
        self.s5 = HASHERS["sha512"](self.msg)

        self.w1 = hs.format_hashset({"blake3": self.b3})
        self.w2 = hs.format_hashset({"sha256": self.s2})
        self.w3 = hs.format_hashset({"blake3": self.b3, "sha256": self.s2})
        self.w4_all = hs.format_hashset({"blake3": self.b3, "sha256": self.s2, "sha3-256": self.s3})
        self.w4_only = hs.format_hashset({"sha3-256": self.s3})
        self.w5_all = hs.format_hashset({"blake3": self.b3, "sha256": self.s2, "sha512": self.s5})
        self.w5_only = hs.format_hashset({"sha512": self.s5})

    def test_r1_sha256_only(self) -> None:
        for w in (self.w2, self.w3, self.w4_all, self.w5_all):
            self.assertEqual(hs.verify_first(w, self.msg, HASHERS, ["sha256"]), "sha256")
        for w in (self.w1, self.w4_only, self.w5_only):
            with self.assertRaises(hs.HashsetError):
                hs.verify_first(w, self.msg, HASHERS, ["sha256"])

    def test_r2_blake3_only(self) -> None:
        for w in (self.w1, self.w3, self.w4_all, self.w5_all):
            self.assertEqual(hs.verify_first(w, self.msg, HASHERS, ["blake3"]), "blake3")
        for w in (self.w2, self.w4_only, self.w5_only):
            with self.assertRaises(hs.HashsetError):
                hs.verify_first(w, self.msg, HASHERS, ["blake3"])

    def test_r3_prefer_blake3_fallback_sha256(self) -> None:
        self.assertEqual(hs.verify_first(self.w1, self.msg, HASHERS, ["blake3", "sha256"]), "blake3")
        self.assertEqual(hs.verify_first(self.w2, self.msg, HASHERS, ["blake3", "sha256"]), "sha256")
        self.assertEqual(hs.verify_first(self.w3, self.msg, HASHERS, ["blake3", "sha256"]), "blake3")
        self.assertEqual(hs.verify_first(self.w4_all, self.msg, HASHERS, ["blake3", "sha256"]), "blake3")
        self.assertEqual(hs.verify_first(self.w5_all, self.msg, HASHERS, ["blake3", "sha256"]), "blake3")
        for w in (self.w4_only, self.w5_only):
            with self.assertRaises(hs.HashsetError):
                hs.verify_first(w, self.msg, HASHERS, ["blake3", "sha256"])

    def test_r4_verify_both_and_fail_on_either(self) -> None:
        self.assertEqual(hs.verify_all(self.w1, self.msg, HASHERS, {"blake3", "sha256"}), ["blake3"])
        self.assertEqual(hs.verify_all(self.w2, self.msg, HASHERS, {"blake3", "sha256"}), ["sha256"])
        self.assertEqual(hs.verify_all(self.w3, self.msg, HASHERS, {"blake3", "sha256"}), ["blake3", "sha256"])
        self.assertEqual(hs.verify_all(self.w4_all, self.msg, HASHERS, {"blake3", "sha256"}), ["blake3", "sha256"])
        self.assertEqual(hs.verify_all(self.w5_all, self.msg, HASHERS, {"blake3", "sha256"}), ["blake3", "sha256"])

        # Tampering with EITHER hash in W3 MUST fail R4.
        bad_s2 = hs.format_hashset({"blake3": self.b3, "sha256": bytes([self.s2[0] ^ 1]) + self.s2[1:]})
        bad_b3 = hs.format_hashset({"blake3": bytes([self.b3[0] ^ 1]) + self.b3[1:], "sha256": self.s2})
        with self.assertRaises(hs.HashsetError):
            hs.verify_all(bad_s2, self.msg, HASHERS, {"blake3", "sha256"})
        with self.assertRaises(hs.HashsetError):
            hs.verify_all(bad_b3, self.msg, HASHERS, {"blake3", "sha256"})

        # R3 intentionally skips sha256 when blake3 is present (valid syntax, good blake3).
        self.assertEqual(hs.verify_first(bad_s2, self.msg, HASHERS, ["blake3", "sha256"]), "blake3")
        # But R3 MUST still reject syntactically malformed trailing entries.
        with self.assertRaises(hs.HashsetError):
            hs.verify_first(f"{self.w1}.sha256-INVALID", self.msg, HASHERS, ["blake3", "sha256"])

    def test_r5_r6_r7_future_algorithms(self) -> None:
        # R5: require sha3-256
        self.assertEqual(hs.verify_first(self.w4_all, self.msg, HASHERS, ["sha3-256"]), "sha3-256")
        self.assertEqual(hs.verify_first(self.w4_only, self.msg, HASHERS, ["sha3-256"]), "sha3-256")
        with self.assertRaises(hs.HashsetError):
            hs.verify_first(self.w3, self.msg, HASHERS, ["sha3-256"])
        with self.assertRaises(hs.HashsetError):
            hs.verify_first(self.w5_all, self.msg, HASHERS, ["sha3-256"])

        # R6: prefer sha3-256, fallback to blake3 then sha256
        r6 = ["sha3-256", "blake3", "sha256"]
        self.assertEqual(hs.verify_first(self.w4_all, self.msg, HASHERS, r6), "sha3-256")
        self.assertEqual(hs.verify_first(self.w4_only, self.msg, HASHERS, r6), "sha3-256")
        self.assertEqual(hs.verify_first(self.w5_all, self.msg, HASHERS, r6), "blake3")
        self.assertEqual(hs.verify_first(self.w2, self.msg, HASHERS, r6), "sha256")
        with self.assertRaises(hs.HashsetError):
            hs.verify_first(self.w5_only, self.msg, HASHERS, r6)

        # R7: verify all of {blake3, sha256, sha3-256} present (ignores unknown sha512)
        r7 = {"blake3", "sha256", "sha3-256"}
        self.assertEqual(hs.verify_all(self.w4_all, self.msg, HASHERS, r7), ["blake3", "sha256", "sha3-256"])
        self.assertEqual(hs.verify_all(self.w4_only, self.msg, HASHERS, r7), ["sha3-256"])
        self.assertEqual(hs.verify_all(self.w5_all, self.msg, HASHERS, r7), ["blake3", "sha256"])
        with self.assertRaises(hs.HashsetError):
            hs.verify_all(self.w5_only, self.msg, HASHERS, r7)


if __name__ == "__main__":
    unittest.main()
