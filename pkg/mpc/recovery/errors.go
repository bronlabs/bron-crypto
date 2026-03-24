package recovery

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument indicates missing or inconsistent inputs.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrFailed captures non-recoverable protocol failures.
	ErrFailed = errs.New("failed")
	// ErrValidation indicates a failure to validate incoming messages.
	ErrValidation = errs.New("validation failed")
)
