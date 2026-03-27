package redistribute

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument indicates invalid input parameters.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrFailed indicates that the protocol could not complete successfully.
	ErrFailed = errs.New("failed")
	// ErrValidation indicates a failure to validate incoming messages or state.
	ErrValidation = errs.New("validation failed")
)
