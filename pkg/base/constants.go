package base

// Base security parameters - these are the source of truth
const (
	// ComputationalSecurityBits (λ) is the number of bits of computational security
	// we want to achieve in most of our cryptographic primitives.
	ComputationalSecurityBits = 128

	// StatisticalSecurityBits (λ_s) is the number of bits of statistical security
	// we want to achieve in most of our cryptographic primitives,
	// applicable mostly to soundness of interactive proofs.
	StatisticalSecurityBits = 80

	// CollisionResistance is the hash digest length to achieve λ-bits of
	// collision resistance (birthday paradox).
	CollisionResistance = 2 * ComputationalSecurityBits

	// TODO: rename the value to something that Mateusz will send later
	// Hash2CurveAppTag is the application tag for hash-to-curve operations
	Hash2CurveAppTag = "bron-crypto/hash2curve"
)

//go:generate go run github.com/bronlabs/bron-crypto/tools/secparams-codegen
