package constants

// ComputationalSecurity is the number of bits of security we want to achieve in most of our cryptographic primitives.
const ComputationalSecurity = 128

// ScalarBytes is the number of bytes needed to represent a scalar in most fields in the `curves` package.
const ScalarBytes = 32

// DigestScalarBytes is the number of bytes needed for safe conversion to a scalar in this field to avoid bias when reduced.
const DigestScalarBytes = 64
