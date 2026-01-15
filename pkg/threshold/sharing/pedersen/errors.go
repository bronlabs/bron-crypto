package pedersen

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	ErrIsNil        = errs2.New("is nil")
	ErrMembership   = errs2.New("membership error")
	ErrFailed       = errs2.New("failed")
	ErrIsZero       = errs2.New("is zero")
	ErrVerification = errs2.New("verification failed")
)
