package primegen

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument reports a structurally invalid request: bit length
	// below MinBits, a malformed lower bound, a bad class, or missing
	// Miller-Rabin round counts.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrIsNil reports a nil PRNG.
	ErrIsNil = errs.New("is nil")
	// ErrFailed reports a violated internal invariant.
	ErrFailed = errs.New("operation failed")
)
