package commitments

import (
	"github.com/bronlabs/errs-go/errs"
)

var (
	ErrVerificationFailed = errs.New("verification failed")
	ErrIsNil              = errs.New("is nil")
	ErrSubGroupMembership = errs.New("not in subgroup")
	ErrInvalidArgument    = errs.New("invalid argument")
)
