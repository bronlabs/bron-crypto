package proofs

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument indicates missing or inconsistent inputs.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrValidationFailed indicates malformed or invalid data.
	ErrValidationFailed = errs.New("validation failed")
	// ErrFailed signals unrecoverable error.
	ErrFailed = errs.New("validation failed")
	// ErrVerificationFailed signals failed proof verification.
	ErrVerificationFailed = errs.New("verification failed")
	// ErrRound is returned when rounds are invoked out of order.
	ErrRound = errs.New("invalid round")
)
