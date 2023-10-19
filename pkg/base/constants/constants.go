package constants

// ComputationalSecurity is the number of bits of security we want to achieve in most of our cryptographic primitives.
const ComputationalSecurity = 128
const ComputationalSecurityBytes = ComputationalSecurity >> 3

// ScalarBytes is the number of bytes needed to represent a scalar in most fields in the `curves` package.
const ScalarBytes = 32

// WideFieldBytes is the number of bytes needed for sufficiently unbiased sampling of a scalar in most fields.
const WideFieldBytes = 64

// Curve names compliant with https://datatracker.ietf.org/doc/html/rfc9380
const (
	BLS12381G1_NAME string = "BLS12381G1"
	BLS12381G2_NAME string = "BLS12381G2"
	K256_NAME       string = "secp256k1"
	P256_NAME       string = "P256"
	CURVE25519_NAME string = "curve25519"
	ED25519_NAME    string = "edwards25519"
	PALLAS_NAME     string = "pallas"
)
