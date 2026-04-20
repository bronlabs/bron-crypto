package znstar

import "github.com/bronlabs/errs-go/errs"

// Package-level sentinel errors. All znstar APIs wrap one of these so that
// callers can distinguish programmer errors (nil pointers), internal failures
// (constant-time primitives reporting ok == false, mismatched moduli, etc.),
// and domain errors (inputs that fail the unit / residuosity / order checks).
var (
	// ErrIsNil is returned whenever a nil pointer is supplied where a concrete
	// value (group, unit, PRNG, …) is required.
	ErrIsNil = errs.New("is nil")
	// ErrFailed signals that a primitive reported a constant-time failure —
	// e.g. a Jacobi computation, non-invertible element, or conversion between
	// known/unknown-order representations that cannot succeed.
	ErrFailed = errs.New("failed")
	// ErrValue signals that a value is structurally valid but out of the
	// expected domain (wrong modulus, not coprime to N, not a quadratic
	// residue when one is required, etc.).
	ErrValue = errs.New("invalid value")
)
