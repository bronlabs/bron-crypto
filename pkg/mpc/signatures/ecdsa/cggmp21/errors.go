package cggmp21

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrNil is returned when a required value is nil or empty.
	ErrNil = errs.New("nil")
	// ErrFailed is returned when an internal CGGMP21 invariant is not satisfied.
	ErrFailed = errs.New("failed")
	// ErrValidationFailed is returned when a value fails CGGMP21 validation.
	ErrValidationFailed = errs.New("validation failed")
	// ErrInvalidRound is returned when an operation is called out of order.
	ErrInvalidRound = errs.New("invalid round")
)
