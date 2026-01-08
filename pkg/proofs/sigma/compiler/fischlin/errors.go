package fischlin

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	ErrNil          = errs2.New("nil")
	ErrInvalid      = errs2.New("invalid")
	ErrFailed       = errs2.New("failed")
	ErrVerification = errs2.New("verification failed")
)
