package nthroot

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrFailed indicates a general failure during protocol execution.
	ErrFailed = errs.New("failed")
	// ErrVerificationFailed signals a failed proof verification.
	ErrVerificationFailed = errs.New("verification failed")
	// ErrInvalidArgument indicates that an invalid argument was provided to a function.
	ErrInvalidArgument = errs.New("invalid argument")
)
