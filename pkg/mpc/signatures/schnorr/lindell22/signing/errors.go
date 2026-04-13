package signing

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrNilArgument is returned when a required argument is nil.
	ErrNilArgument = errs.New("nil argument")
	// ErrInvalidRound is returned when an operation is attempted in the wrong round.
	ErrInvalidRound = errs.New("invalid round")
	// ErrInvalidType is returned when a type assertion or check fails.
	ErrInvalidType = errs.New("invalid type")
	// ErrInvalidMembership is returned when a party is not authorized for an operation.
	ErrInvalidMembership = errs.New("invalid membership")
	// ErrValidation is returned when message validation fails.
	ErrValidation = errs.New("validation failed")
)
