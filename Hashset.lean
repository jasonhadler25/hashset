/-!
# Hashset Formal Specification (Lean 4)

Self-contained, executable specification of the Hashset wire format,
canonical unpadded lowercase RFC 4648 Base32, strict parser/encoder,
reader verification policies (R1–R7), and formal specification properties.
-/

namespace Hashset

/-! ## 1. Character Predicates & Algorithm Names -/

def isLowerAlpha (c : Char) : Bool :=
  'a' ≤ c && c ≤ 'z'

def isAsciiDigit (c : Char) : Bool :=
  '0' ≤ c && c ≤ '9'

def isAlgBodyChar (c : Char) : Bool :=
  isLowerAlpha c || isAsciiDigit c

/-- Matches ABNF: `lalpha *( lalpha / digit ) *( "-" 1*( lalpha / digit ) )`. -/
def isValidAlgName : List Char → Bool
  | [] => false
  | c :: rest => isLowerAlpha c && go false rest
where
  go (prevHyphen : Bool) : List Char → Bool
    | [] => !prevHyphen
    | c :: rest =>
      if c == '-' then
        if prevHyphen then false else go true rest
      else if isAlgBodyChar c then
        go false rest
      else
        false

/-- Strict unsigned ASCII bytewise lexicographical order. -/
def asciiLt : List Char → List Char → Bool
  | [], [] => false
  | [], _ :: _ => true
  | _ :: _, [] => false
  | a :: as, b :: bs =>
    if a.toNat < b.toNat then true
    else if a.toNat > b.toNat then false
    else asciiLt as bs

/-! ## 2. Canonical Unpadded Lowercase Base32 (RFC 4648 §6 & §3.5) -/

/-- Encode a 5-bit value `n < 32` into lowercase RFC 4648 Base32. -/
def b32EncodeDigit (n : Nat) : Char :=
  if n < 26 then Char.ofNat ('a'.toNat + n)
  else Char.ofNat ('2'.toNat + (n - 26))

/-- Decode a single lowercase RFC 4648 Base32 character into `0..31`. -/
def b32DecodeChar (c : Char) : Option Nat :=
  if 'a' ≤ c && c ≤ 'z' then some (c.toNat - 'a'.toNat)
  else if '2' ≤ c && c ≤ '7' then some (26 + (c.toNat - '2'.toNat))
  else none

/-- Canonical unpadded lowercase Base32 encoder (5 bytes ↔ 8 chars). -/
def b32Encode : List UInt8 → List Char
  | [] => []
  | [b0] =>
    let x0 := b0.toNat
    [ b32EncodeDigit (x0 >>> 3)
    , b32EncodeDigit ((x0 &&& 0x07) <<< 2) ]
  | [b0, b1] =>
    let x0 := b0.toNat; let x1 := b1.toNat
    [ b32EncodeDigit (x0 >>> 3)
    , b32EncodeDigit (((x0 &&& 0x07) <<< 2) ||| (x1 >>> 6))
    , b32EncodeDigit ((x1 >>> 1) &&& 0x1F)
    , b32EncodeDigit ((x1 &&& 0x01) <<< 4) ]
  | [b0, b1, b2] =>
    let x0 := b0.toNat; let x1 := b1.toNat; let x2 := b2.toNat
    [ b32EncodeDigit (x0 >>> 3)
    , b32EncodeDigit (((x0 &&& 0x07) <<< 2) ||| (x1 >>> 6))
    , b32EncodeDigit ((x1 >>> 1) &&& 0x1F)
    , b32EncodeDigit (((x1 &&& 0x01) <<< 4) ||| (x2 >>> 4))
    , b32EncodeDigit ((x2 &&& 0x0F) <<< 1) ]
  | [b0, b1, b2, b3] =>
    let x0 := b0.toNat; let x1 := b1.toNat; let x2 := b2.toNat; let x3 := b3.toNat
    [ b32EncodeDigit (x0 >>> 3)
    , b32EncodeDigit (((x0 &&& 0x07) <<< 2) ||| (x1 >>> 6))
    , b32EncodeDigit ((x1 >>> 1) &&& 0x1F)
    , b32EncodeDigit (((x1 &&& 0x01) <<< 4) ||| (x2 >>> 4))
    , b32EncodeDigit (((x2 &&& 0x0F) <<< 1) ||| (x3 >>> 7))
    , b32EncodeDigit ((x3 >>> 2) &&& 0x1F)
    , b32EncodeDigit ((x3 &&& 0x03) <<< 3) ]
  | b0 :: b1 :: b2 :: b3 :: b4 :: rest =>
    let x0 := b0.toNat; let x1 := b1.toNat; let x2 := b2.toNat
    let x3 := b3.toNat; let x4 := b4.toNat
    [ b32EncodeDigit (x0 >>> 3)
    , b32EncodeDigit (((x0 &&& 0x07) <<< 2) ||| (x1 >>> 6))
    , b32EncodeDigit ((x1 >>> 1) &&& 0x1F)
    , b32EncodeDigit (((x1 &&& 0x01) <<< 4) ||| (x2 >>> 4))
    , b32EncodeDigit (((x2 &&& 0x0F) <<< 1) ||| (x3 >>> 7))
    , b32EncodeDigit ((x3 >>> 2) &&& 0x1F)
    , b32EncodeDigit (((x3 &&& 0x03) <<< 3) ||| (x4 >>> 5))
    , b32EncodeDigit (x4 &&& 0x1F) ] ++ b32Encode rest

/-- Decode validated 5-bit values, rejecting invalid remainders & non-zero trailing bits. -/
def b32DecodeVals : List Nat → Option (List UInt8)
  | [] => some []
  | [c0, c1] =>
    if (c1 &&& 0x03) != 0 then none
    else some [UInt8.ofNat ((c0 <<< 3) ||| (c1 >>> 2))]
  | [c0, c1, c2, c3] =>
    if (c3 &&& 0x0F) != 0 then none
    else some
      [ UInt8.ofNat ((c0 <<< 3) ||| (c1 >>> 2))
      , UInt8.ofNat (((c1 &&& 0x03) <<< 6) ||| (c2 <<< 1) ||| (c3 >>> 4)) ]
  | [c0, c1, c2, c3, c4] =>
    if (c4 &&& 0x01) != 0 then none
    else some
      [ UInt8.ofNat ((c0 <<< 3) ||| (c1 >>> 2))
      , UInt8.ofNat (((c1 &&& 0x03) <<< 6) ||| (c2 <<< 1) ||| (c3 >>> 4))
      , UInt8.ofNat (((c3 &&& 0x0F) <<< 4) ||| (c4 >>> 1)) ]
  | [c0, c1, c2, c3, c4, c5, c6] =>
    if (c6 &&& 0x07) != 0 then none
    else some
      [ UInt8.ofNat ((c0 <<< 3) ||| (c1 >>> 2))
      , UInt8.ofNat (((c1 &&& 0x03) <<< 6) ||| (c2 <<< 1) ||| (c3 >>> 4))
      , UInt8.ofNat (((c3 &&& 0x0F) <<< 4) ||| (c4 >>> 1))
      , UInt8.ofNat (((c4 &&& 0x01) <<< 7) ||| (c5 <<< 2) ||| (c6 >>> 3)) ]
  | c0 :: c1 :: c2 :: c3 :: c4 :: c5 :: c6 :: c7 :: rest => do
    let tail ← b32DecodeVals rest
    pure
      ( UInt8.ofNat ((c0 <<< 3) ||| (c1 >>> 2))
      :: UInt8.ofNat (((c1 &&& 0x03) <<< 6) ||| (c2 <<< 1) ||| (c3 >>> 4))
      :: UInt8.ofNat (((c3 &&& 0x0F) <<< 4) ||| (c4 >>> 1))
      :: UInt8.ofNat (((c4 &&& 0x01) <<< 7) ||| (c5 <<< 2) ||| (c6 >>> 3))
      :: UInt8.ofNat (((c6 &&& 0x07) <<< 5) ||| c7)
      :: tail )
  | _ => none  -- rejects lengths 1, 3, 6 mod 8

/-- Strict canonical unpadded lowercase Base32 decoder (rejects empty input). -/
def b32Decode (cs : List Char) : Option (List UInt8) :=
  if cs.isEmpty then none
  else do
    let vals ← cs.mapM b32DecodeChar
    b32DecodeVals vals

/-! ## 3. Core Data Model, Parser, and Encoder -/

structure Entry where
  alg    : String
  digest : List UInt8
  deriving Repr, DecidableEq

def isValidEntry (e : Entry) : Bool :=
  isValidAlgName e.alg.toList && !e.digest.isEmpty

def isStrictlySorted : List Entry → Bool
  | [] => true
  | [_] => true
  | e1 :: e2 :: rest =>
    asciiLt e1.alg.toList e2.alg.toList && isStrictlySorted (e2 :: rest)

/-- A valid, canonical Hashset: non-empty, valid entries, strictly ASCII-sorted by `alg`. -/
structure HashSet where
  entries        : List Entry
  nonEmpty       : entries ≠ []
  entriesValid   : entries.all isValidEntry = true
  strictlySorted : isStrictlySorted entries = true
  deriving Repr

instance : DecidableEq HashSet := fun a b =>
  match decEq a.entries b.entries with
  | isTrue h => isTrue (by cases a; cases b; cases h; rfl)
  | isFalse h => isFalse (fun heq => h (congrArg HashSet.entries heq))

def HashSet.lookup (hs : HashSet) (alg : String) : Option (List UInt8) :=
  (hs.entries.find? (fun e => e.alg == alg)).map (·.digest)

private def splitOnChar (sep : Char) (cs : List Char) : List (List Char) :=
  let rec go (acc : List Char) : List Char → List (List Char)
    | [] => [acc.reverse]
    | c :: rest =>
      if c == sep then acc.reverse :: go [] rest
      else go (c :: acc) rest
  go [] cs

private def splitOnce (sep : Char) (cs : List Char) : Option (List Char × List Char) :=
  let rec go (acc : List Char) : List Char → Option (List Char × List Char)
    | [] => none
    | c :: rest =>
      if c == sep then some (acc.reverse, rest)
      else go (c :: acc) rest
  go [] cs

/-- Split on the LAST occurrence of `sep`. -/
private def rsplitOnce (sep : Char) (cs : List Char) : Option (List Char × List Char) :=
  match splitOnce sep cs.reverse with
  | none => none
  | some (revRight, revLeft) => some (revLeft.reverse, revRight.reverse)

private def parseEntry (cs : List Char) : Option Entry := do
  let (algCs, digCs) ← rsplitOnce '-' cs
  guard (isValidAlgName algCs)
  let raw ← b32Decode digCs
  guard (!raw.isEmpty)
  pure { alg := String.ofList algCs, digest := raw }

/-- Strict parser (Section 3.1). Validates the entire string before returning `some`. -/
def parse (s : String) : Option HashSet := do
  let cs := s.toList
  guard (!cs.isEmpty)
  guard (cs.all (fun c => c.toNat < 128))
  let entries ← (splitOnChar '.' cs).mapM parseEntry
  if hne : entries ≠ [] then
    if hv : entries.all isValidEntry = true then
      if hs : isStrictlySorted entries = true then
        some ⟨entries, hne, hv, hs⟩
      else none
    else none
  else none

/-- Canonical encoder (Section 3.2). -/
def formatEntry (e : Entry) : List Char :=
  e.alg.toList ++ ['-'] ++ b32Encode e.digest

def format (hs : HashSet) : String :=
  String.ofList (List.intercalate ['.'] (hs.entries.map formatEntry))

/-! ## 4. Verification Semantics & Standard Readers (R1–R7) -/

/-- Abstract hash-function oracle mapping algorithm names to fixed-output hash functions. -/
abbrev HashOracle := String → Option (List UInt8 → List UInt8)

def verifyEntry (oracle : HashOracle) (msg : List UInt8) (e : Entry) : Bool :=
  match oracle e.alg with
  | none   => false
  | some h => h msg == e.digest

/-- Priority-fallback verifier: checks the highest-priority present algorithm; fails if none. -/
def verifyFirst (oracle : HashOracle) (priority : List String)
    (wire : String) (msg : List UInt8) : Bool :=
  match parse wire with
  | none    => false
  | some hs =>
    match priority.find? (fun a => (hs.lookup a).isSome) with
    | none     => false
    | some alg =>
      match hs.lookup alg, oracle alg with
      | some expected, some h => h msg == expected
      | _, _                  => false

/-- Verify-all-supported verifier: checks every supported algorithm present (ignoring unknown ones).
    Fails if zero supported algorithms are present OR if any selected algorithm mismatches. -/
def verifyAll (oracle : HashOracle) (supported : List String)
    (wire : String) (msg : List UInt8) : Bool :=
  match parse wire with
  | none    => false
  | some hs =>
    let selected := hs.entries.filter (fun e => supported.contains e.alg)
    !selected.isEmpty && selected.all (verifyEntry oracle msg)

-- Concrete reader instantiations (R1–R7):
def verifyR1 (o : HashOracle) := verifyFirst o ["sha256"]
def verifyR2 (o : HashOracle) := verifyFirst o ["blake3"]
def verifyR3 (o : HashOracle) := verifyFirst o ["blake3", "sha256"]
def verifyR4 (o : HashOracle) := verifyAll   o ["blake3", "sha256"]
def verifyR5 (o : HashOracle) (newAlg : String) := verifyFirst o [newAlg]
def verifyR6 (o : HashOracle) (newAlg : String) := verifyFirst o [newAlg, "blake3", "sha256"]
def verifyR7 (o : HashOracle) (newAlg : String) := verifyAll   o ["blake3", "sha256", newAlg]

/-! ## 5. Formal Specification Properties -/

namespace Spec

/-- Base32 round-trip for every non-empty byte list. -/
def Base32RoundTrip : Prop :=
  ∀ bs : List UInt8, bs ≠ [] → b32Decode (b32Encode bs) = some bs

/-- Base32 canonical uniqueness: two strings decoding to the same bytes are identical. -/
def Base32CanonicalUnique : Prop :=
  ∀ s₁ s₂ : List Char, ∀ bs : List UInt8,
    b32Decode s₁ = some bs → b32Decode s₂ = some bs → s₁ = s₂

/-- Hashset format/parse round-trip. -/
def RoundTrip : Prop :=
  ∀ hs : HashSet, parse (format hs) = some hs

/-- Canonical wire uniqueness: every valid Hashset has exactly one wire encoding. -/
def CanonicalUnique : Prop :=
  ∀ s₁ s₂ : String, ∀ hs : HashSet,
    parse s₁ = some hs → parse s₂ = some hs → s₁ = s₂

/-- R4/R7 fail-closed soundness: if ANY supported entry in the hashset mismatches,
    `verifyAll` MUST return `false`. -/
def VerifyAllRejectsAnyMismatch : Prop :=
  ∀ (o : HashOracle) (supported : List String) (wire : String) (hs : HashSet)
    (msg : List UInt8) (e : Entry),
    parse wire = some hs →
    e ∈ hs.entries →
    supported.contains e.alg = true →
    verifyEntry o msg e = false →
    verifyAll o supported wire msg = false

/-- Forward compatibility (W4/W5): adding valid entries whose algorithms are NOT in
    `supported` (or `priority`) preserves the verification result of `verifyAll`
    (and `verifyFirst`). -/
def ForwardCompatVerifyAll : Prop :=
  ∀ (o : HashOracle) (supported : List String) (hs₁ hs₂ : HashSet) (msg : List UInt8),
    hs₁.entries.filter (fun e => supported.contains e.alg) =
    hs₂.entries.filter (fun e => supported.contains e.alg) →
    verifyAll o supported (format hs₁) msg = verifyAll o supported (format hs₂) msg

def ForwardCompatVerifyFirst : Prop :=
  ∀ (o : HashOracle) (priority : List String) (hs₁ hs₂ : HashSet) (msg : List UInt8),
    (∀ a, priority.contains a = true → hs₁.lookup a = hs₂.lookup a) →
    verifyFirst o priority (format hs₁) msg = verifyFirst o priority (format hs₂) msg

end Spec

end Hashset
