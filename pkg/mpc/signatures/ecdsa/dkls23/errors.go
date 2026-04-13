package dkls23

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrFailed represents failed.
	ErrFailed = errs.New("failed")
	// ErrValidationFailed represents validation failed.
	ErrValidationFailed = errs.New("validation failed")
	// ErrNil represents nil.
	ErrNil = errs.New("nil")
	// ErrRandomSample represents random sample failed.
	ErrRandomSample = errs.New("random sample failed")
	// ErrHashing represents hashing failed.
	ErrHashing = errs.New("hashing failed")
)
