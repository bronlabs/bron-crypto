package sharing

import "github.com/bronlabs/errs-go/errs"

var (
	ErrIsNil        = errs.New("is nil")
	ErrValue        = errs.New("invalid value")
	ErrMembership   = errs.New("membership error")
	ErrFailed       = errs.New("failed")
	ErrArgument     = errs.New("invalid argument")
	ErrVerification = errs.New("verification failed")
	ErrType         = errs.New("type error")
	ErrUnauthorized = errs.New("unauthorised")
	ErrIsZero       = errs.New("is zero")
)
