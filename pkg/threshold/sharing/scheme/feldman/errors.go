package feldman

import "github.com/bronlabs/errs-go/errs"

var (
	ErrIsNil        = errs.New("is nil")
	ErrMembership   = errs.New("membership error")
	ErrFailed       = errs.New("failed")
	ErrArgument     = errs.New("invalid argument")
	ErrVerification = errs.New("verification failed")
)
