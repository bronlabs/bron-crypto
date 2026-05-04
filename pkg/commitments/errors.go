package commitments

import (
	"github.com/bronlabs/errs-go/errs"
)

var (
	ErrVerificationFailed = errs.New("verification failed")
	ErrIsNil              = errs.New("is nil")
	ErrInvalidArgument    = errs.New("invalid argument")
)
