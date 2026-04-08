package hjky

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument indicates missing or inconsistent inputs.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrFailed captures non-recoverable protocol failures.
	ErrFailed = errs.New("failed")
	// ErrRound is returned when rounds are invoked out of order.
	ErrRound = errs.New("invalid round")
	// ErrValidationFailed indicates a failure to validate incoming messages.
	ErrValidationFailed = errs.New("validation failed")
)
