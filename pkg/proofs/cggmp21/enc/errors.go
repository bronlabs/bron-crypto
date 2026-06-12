package enc

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument indicates missing or inconsistent protocol inputs.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrValidationFailed indicates that a statement/witness pair is malformed or inconsistent.
	ErrValidationFailed = errs.New("validation failed")
	// ErrVerificationFailed indicates a failed sigma-protocol verification.
	ErrVerificationFailed = errs.New("verification failed")
)
