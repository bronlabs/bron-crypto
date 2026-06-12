package cggmp21

import "github.com/bronlabs/errs-go/errs"

var (
	ErrIsNil  = errs.New("is nil")
	ErrFailed = errs.New("failed")
	// ErrValidationFailed represents validation failed.
	ErrValidationFailed = errs.New("validation failed")
	// ErrNil represents nil.
	ErrNil = errs.New("nil")
	// ErrRandomSample represents random sample failed.
)
