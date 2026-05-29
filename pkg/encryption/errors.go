package encryption

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrIsNil indicates a required argument (key, plaintext, nonce, prng, …) was nil.
	ErrIsNil = errs.New("is nil")
	// ErrOutOfRange indicates a value — typically a plaintext — fell outside its
	// valid range for the scheme.
	ErrOutOfRange = errs.New("is out of range")
	// ErrSubGroupMembership indicates a value is not a member of its expected group.
	// For group-based schemes, accepting such a value can break correctness or
	// security, so this is a validation / deserialization trust-boundary failure.
	ErrSubGroupMembership = errs.New("invalid subgroup membership")
	// ErrFailed indicates an operation failed, e.g. a non-invertible element
	// encountered during key precomputation.
	ErrFailed = errs.New("operation failed")
)
