package base

// Base security parameters - these are the source of truth.
const (
	// ComputationalSecurityBits (λ) is the number of bits of computational security
	// we want to achieve in most of our cryptographic primitives.
	ComputationalSecurityBits = 128

	// StatisticalSecurityBits (λ_s) is the number of bits of statistical security
	// we want to achieve in most of our cryptographic primitives,
	// applicable mostly to soundness of interactive proofs.
	StatisticalSecurityBits = 80

	// IFCKeyLength is the key length (in bits) for integer factorization based cryptography
	// (e.g. RSA) to achieve λ-bits of security.
	// Values based on SP 800-57 Part 1 Rev. 5, Table 2.
	IFCKeyLength = 3072

	// CollisionResistance is the hash digest length to achieve λ-bits of
	// collision resistance (birthday paradox).
	CollisionResistance = 2 * ComputationalSecurityBits

	// TODO: rename the value to something that Mateusz will send later
	// Hash2CurveAppTag is the application tag for hash-to-curve operations.
	Hash2CurveAppTag = "bron_crypto_with-"
)

//go:generate go run github.com/bronlabs/bron-crypto/tools/secparams-codegen
