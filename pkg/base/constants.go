package base

import (
	"golang.org/x/crypto/sha3"
)

// ComputationalSecurity is the number of bits of security we want to achieve in most of our cryptographic primitives.
const ComputationalSecurity = 128
const ComputationalSecurityBytes = ComputationalSecurity / 8

// FieldBytes is the number of bytes needed to represent a FieldElement|Scalar in most fields of the `curves` package.
const FieldBytes = 32

// WideFieldBytes is the number of bytes needed for sufficiently unbiased sampling of a FieldElement|Scalar in most fields.
const WideFieldBytes = 64

// Library-wide tag for Hash2Curve hashing as Random Oracle.
const HASH2CURVE_APP_TAG = "KRYPTON-H2C-"

// Choices of hash functions.
var (
	CommitmentHashFunction   = sha3.New256
	TranscriptHashFunction   = sha3.New256
	RandomOracleHashFunction = sha3.New256
)
