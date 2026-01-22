package tecdsa

import "github.com/bronlabs/errs-go/pkg/errs"

var (
	// ErrFailed represents failed.
	ErrFailed = errs.New("failed")
	// ErrNil represents nil.
	ErrNil = errs.New("nil")
)
