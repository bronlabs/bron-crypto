package signing

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument is returned when a constructor or round receives an
	// argument that violates its documented contract.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrValidation is returned when an incoming message fails validation.
	ErrValidation = errs.New("validation failed")
	// ErrRound is returned when a round is invoked out of order.
	ErrRound = errs.New("invalid round")
)
