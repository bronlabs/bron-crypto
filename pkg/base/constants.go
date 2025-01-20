package base

import (
	"golang.org/x/crypto/sha3"
)

// ComputationalSecurity (λ) is the number of bits of computational security we want to achieve in most of our cryptographic primitives.
const ComputationalSecurity = 128
const ComputationalSecurityLog2 = 7

// StatisticalSecurity (λ_s) is the number of bits of statistical security we want to achieve in most of our cryptographic primitives, applicable mostly to soundness of interactive proofs.
const StatisticalSecurity = 80

// CollisionResistance is the hash digest length to achieve λ-bits of collision resistance (birthday paradox).
const CollisionResistance = 2 * ComputationalSecurity
const CollisionResistanceBytes = CollisionResistance / 8

// Hash2CurveAppTag is a library-wide tag for Hash2Curve hashing as Random Oracle.
const Hash2CurveAppTag = "bronlabs-krypton-primitives-with-"

// Choices of hash functions.
var (
	// RandomOracleHashFunction is used as a Random Oracle in most of the cryptographic primitives. Output length MUST be >= CollisionResistanceBytes.
	RandomOracleHashFunction = sha3.New256
)
