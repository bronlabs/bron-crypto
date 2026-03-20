package session

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument indicates invalid input parameters.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrRound indicates a round failure due to missing or invalid data.
	ErrRound = errs.New("round failure")
	// ErrValidation indicates a failure to validate incoming messages.
	ErrValidation = errs.New("validation failed")
)
