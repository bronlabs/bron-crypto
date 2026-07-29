package lindell17

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument indicates missing or inconsistent inputs.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrFailed indicates a general failure during protocol execution.
	ErrFailed = errs.New("failed")
)
