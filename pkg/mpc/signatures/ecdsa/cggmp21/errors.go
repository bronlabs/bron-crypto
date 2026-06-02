package cggmp21

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrValidationFailed represents validation failed.
	ErrValidationFailed = errs.New("validation failed")
	// ErrNil represents nil.
	ErrNil = errs.New("nil")
	// ErrFailed represents generic failure.
	ErrFailed = errs.New("failed")
	// ErrRound represents invalid round.
	ErrRound = errs.New("invalid round")
)
