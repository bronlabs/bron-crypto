package prm

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument indicates missing protocol inputs.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrValidationFailed signals malformed or inconsistent protocol inputs.
	ErrValidationFailed = errs.New("validation failed")
	// ErrVerificationFailed signals failed proof verification.
	ErrVerificationFailed = errs.New("verification failed")
)
