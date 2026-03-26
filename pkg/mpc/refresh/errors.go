package refresh

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrRound indicates that a participant received messages for an unexpected round.
	ErrRound = errs.New("invalid round")
	// ErrInvalidArgument indicates missing or inconsistent inputs.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrValidation indicates a failure to validate incoming messages.
	ErrValidation = errs.New("validation failed")
)
