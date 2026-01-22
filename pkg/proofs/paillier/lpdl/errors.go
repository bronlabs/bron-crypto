package lpdl

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument indicates missing or inconsistent inputs.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrRound is returned when rounds are invoked out of order.
	ErrRound = errs.New("invalid round")
	// ErrVerificationFailed signals a failed proof verification.
	ErrVerificationFailed = errs.New("verification failed")
	// ErrFailed indicates a general failure during protocol execution.
	ErrFailed = errs.New("failed")
)
