package sign_softspoken

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	// ErrFailed represents failed.
	ErrFailed = errs2.New("failed")
	// ErrValidation represents validation failed.
	ErrValidation = errs2.New("validation failed")
	// ErrNil represents nil.
	ErrNil = errs2.New("nil")
	// ErrRandomSample represents random sample failed.
	ErrRandomSample = errs2.New("random sample failed")
	// ErrHashing represents hashing failed.
	ErrHashing = errs2.New("hashing failed")
)
