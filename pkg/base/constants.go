package base

import (
	"golang.org/x/crypto/sha3"
)

// ComputationalSecurity (λ) is the number of bits of comptational security we want to achieve in most of our cryptographic primitives.
const ComputationalSecurity = 128
const ComputationalSecurityLog2 = 7

// StatisticalSecurity (λ_s) is the number of bits of statistical security we want to achieve in most of our cryptographic primitives, applicable mostly to soundness of interactive proofs.
const StatisticalSecurity = 80

// CollisionResistance is the hash digest length to achieve λ-bits of collision resistance (birthday paradox).
const CollisionResistance = 2 * ComputationalSecurity
const CollisionResistanceBytes = CollisionResistance / 8

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
