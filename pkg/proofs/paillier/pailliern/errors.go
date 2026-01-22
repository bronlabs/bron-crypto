package pailliern

import "github.com/bronlabs/errs-go/pkg/errs"

var (
	// ErrInvalidArgument indicates missing or inconsistent inputs.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrVerificationFailed signals a failed proof verification.
	ErrVerificationFailed = errs.New("verification failed")
	// ErrFailed indicates a general failure during protocol execution.
	ErrFailed = errs.New("failed")
)
