package lp

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	// ErrInvalidArgument indicates missing or inconsistent inputs.
	ErrInvalidArgument = errs2.New("invalid argument")
	// ErrRound is returned when rounds are invoked out of order.
	ErrRound = errs2.New("invalid round")
	// ErrVerificationFailed signals a failed proof verification.
	ErrVerificationFailed = errs2.New("verification failed")
	// ErrFailed indicates a general failure during protocol execution.
	ErrFailed = errs2.New("failed")
)
