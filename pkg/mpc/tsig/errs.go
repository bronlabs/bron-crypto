package tsig

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument is returned when a function receives an invalid argument.
	ErrInvalidArgument = errs.New("invalid argument")
)
