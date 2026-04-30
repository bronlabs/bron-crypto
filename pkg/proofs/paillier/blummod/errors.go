package blummod

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument indicates missing or structurally inconsistent inputs.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrValidationFailed indicates that a statement and witness do not match.
	ErrValidationFailed = errs.New("validation failed")
	// ErrVerificationFailed indicates that a proof transcript is invalid.
	ErrVerificationFailed = errs.New("verification failed")
	// ErrFailed indicates an internal arithmetic failure.
	ErrFailed = errs.New("failed")
)
