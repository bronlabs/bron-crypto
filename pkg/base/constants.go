package base

import (
	"golang.org/x/crypto/sha3"
)

// ComputationalSecurity (κ) is the number of bits of security we want to achieve in most of our cryptographic primitives.
const ComputationalSecurity = 128
const ComputationalSecurityBytes = ComputationalSecurity / 8
const CollisionResistanceBytes = 2 * ComputationalSecurityBytes // Achieve κ-bits of collision resistance (birthday paradox)
// TODO: use CollisionResistanceBytes for Digest sizes across the repo.

// FieldBytes is the number of bytes needed to represent a FieldElement|Scalar in most fields of the `curves` package.
const FieldBytes = 32

// WideFieldBytes is the maximum number of bytes accepted for sufficiently unbiased sampling of a FieldElement|Scalar in most fields.
const WideFieldBytes = 64

// Library-wide tag for Hash2Curve hashing as Random Oracle.
const HASH2CURVE_APP_TAG = "KRYPTON-H2C-"

// Choices of hash functions.
var (
	CommitmentHashFunction   = sha3.New256 // Use the `commitments` package for a UC-secure commitment scheme which chains HMACs from `CommitmentHashFunction` and enforces presence of a session-id.
	TranscriptXofFunction    = sha3.NewShake256
	RandomOracleHashFunction = sha3.New256
)
