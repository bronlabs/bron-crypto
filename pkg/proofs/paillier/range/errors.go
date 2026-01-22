package paillierrange

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument indicates missing or inconsistent inputs.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrValidationFailed signals malformed or inconsistent protocol inputs.
	ErrValidationFailed = errs.New("validation failed")
	// ErrVerificationFailed signals failed proof verification.
	ErrVerificationFailed = errs.New("verification failed")
	// ErrFailed indicates a general failure during protocol execution.
	ErrFailed = errs.New("failed")
)
