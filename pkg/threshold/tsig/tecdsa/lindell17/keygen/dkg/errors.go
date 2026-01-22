package dkg

import "github.com/bronlabs/errs-go/pkg/errs"

var (
	// ErrInvalidArgument indicates missing or inconsistent inputs.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrRound is returned when rounds are invoked out of order.
	ErrRound = errs.New("invalid round")
	// ErrMissing indicates required data is missing.
	ErrMissing = errs.New("missing")
	// ErrFailed indicates a general failure during protocol execution.
	ErrFailed = errs.New("failed")
)
