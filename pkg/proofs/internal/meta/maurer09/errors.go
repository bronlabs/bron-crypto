package maurer09

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument indicates missing or inconsistent inputs.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrValidationFails indicates malformed or invalid data.
	ErrValidationFails = errs.New("validation failed")
	// ErrFailed signals unrecoverable error.
	ErrFailed = errs.New("validation failed")
	// ErrVerificationFailed signals failed proof verification.
	ErrVerificationFailed = errs.New("verification failed")
)
