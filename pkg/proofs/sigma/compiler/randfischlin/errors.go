package randfischlin

import "github.com/bronlabs/errs-go/errs"

var (
	ErrNil          = errs.New("nil")
	ErrInvalid      = errs.New("invalid")
	ErrFailed       = errs.New("failed")
	ErrVerification = errs.New("verification failed")
)
