package rvole_bbot

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrFailed represents failed.
	ErrFailed = errs.New("failed")
	// ErrValidation represents validation failed.
	ErrValidation = errs.New("validation failed")
	// ErrInvalidType represents invalid type.
	ErrInvalidType = errs.New("invalid type")
	// ErrNil represents nil.
	ErrNil = errs.New("nil")
	// ErrRandomSample represents random sample failed.
	ErrRandomSample = errs.New("random sample failed")
)
