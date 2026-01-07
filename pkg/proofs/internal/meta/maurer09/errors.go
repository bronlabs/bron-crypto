package maurer09

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	// ErrInvalidArgument indicates missing or inconsistent inputs.
	ErrInvalidArgument = errs2.New("invalid argument")
	// ErrValidationFails indicates malformed or invalid data.
	ErrValidationFails = errs2.New("validation failed")
	// ErrFailed signals unrecoverable error.
	ErrFailed = errs2.New("validation failed")
	// ErrVerificationFailed signals failed proof verification.
	ErrVerificationFailed = errs2.New("verification failed")
)
