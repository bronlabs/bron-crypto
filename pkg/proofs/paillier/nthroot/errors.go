package nthroot

import "github.com/bronlabs/errs-go/pkg/errs"

var (
	// ErrFailed indicates a general failure during protocol execution.
	ErrFailed = errs.New("failed")
	// ErrVerificationFailed signals a failed proof verification.
	ErrVerificationFailed = errs.New("verification failed")
)
