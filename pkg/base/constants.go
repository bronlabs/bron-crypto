package base

import (
	"golang.org/x/crypto/sha3"
)

// ComputationalSecurity (κ) is the number of bits of security we want to achieve in most of our cryptographic primitives.
const ComputationalSecurity = 128
const ComputationalSecurityBytes = ComputationalSecurity / 8
const ComputationalSecurityLog2 = 7

// CollisionResistance is the hash digest length to achieve κ-bits of collision resistance (birthday paradox).
const CollisionResistance = 2 * ComputationalSecurity
const CollisionResistanceBytes = 2 * ComputationalSecurityBytes

// FieldBytes is the number of bytes needed to represent a FieldElement|Scalar in most fields of the `curves` package.
const FieldBytes = 32

// WideFieldBytes is the maximum number of bytes accepted for sufficiently unbiased sampling of a FieldElement|Scalar in most fields.
const WideFieldBytes = 64

// Library-wide tag for Hash2Curve hashing as Random Oracle.
const HASH2CURVE_APP_TAG = "KRYPTON-H2C-"

// Choices of hash functions.
var (
	// RandomOracleHashFunction is used as a Random Oracle in most of the cryptographic primitives. Output length MUST be >= CollisionResistanceBytes.
	RandomOracleHashFunction = sha3.New256
)

// type Nat = integer.Nat[impl_bigint.Set, impl_bigint.Num]
