package nthroot

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	// ErrFailed indicates a general failure during protocol execution.
	ErrFailed = errs2.New("failed")
	// ErrVerificationFailed signals a failed proof verification.
	ErrVerificationFailed = errs2.New("verification failed")
)
