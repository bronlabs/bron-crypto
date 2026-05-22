package fac

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument indicates that an input is nil or malformed.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrValidationFailed indicates that the statement or witness is invalid.
	ErrValidationFailed = errs.New("validation failed")
	// ErrVerificationFailed indicates that a transcript failed verification.
	ErrVerificationFailed = errs.New("verification failed")
)
