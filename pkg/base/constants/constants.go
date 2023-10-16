package constants

// ComputationalSecurity is the number of bits of security we want to achieve in most of our cryptographic primitives.
const ComputationalSecurity = 128
const ComputationalSecurityBytes = ComputationalSecurity >> 3

// ScalarBytes is the number of bytes needed to represent a scalar in most fields in the `curves` package.
const ScalarBytes = 32

// WideFieldBytes is the number of bytes needed for sufficiently unbiased sampling of a scalar in most fields.
const WideFieldBytes = 64
