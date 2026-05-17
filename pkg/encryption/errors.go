package encryption

import "github.com/bronlabs/errs-go/errs"

var (
	ErrIsNil              = errs.New("is nil")
	ErrOutOfRange         = errs.New("is out of range")
	ErrSubGroupMembership = errs.New("invalid subgroup membership")
	ErrFailed             = errs.New("operation failed")
)
