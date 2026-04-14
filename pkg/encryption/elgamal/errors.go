package elgamal

import "github.com/bronlabs/errs-go/errs"

// Sentinel errors returned by constructors and operations.
var (
	// ErrIsNil indicates a required argument was nil.
	ErrIsNil = errs.New("is nil")
	// ErrSubGroupMembership indicates an element failed prime-order subgroup
	// validation (identity or torsion point).
	ErrSubGroupMembership = errs.New("invalid subgroup membership")
	// ErrValue indicates a value violated a domain constraint (e.g. zero nonce).
	ErrValue = errs.New("invalid value")
)
