package nt

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument reports a structurally invalid request: a bit length
	// or key length outside the supported range, or an odd keyLen.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrIsNil reports a nil structure or PRNG argument.
	ErrIsNil = errs.New("is nil")
	// ErrFailed reports a violated internal invariant.
	ErrFailed = errs.New("operation failed")
)
