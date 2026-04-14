package elgamal

import "github.com/bronlabs/errs-go/errs"

var (
	ErrIsNil              = errs.New("is nil")
	ErrSubGroupMembership = errs.New("invalid subgroup membership")
	ErrValue              = errs.New("invalid value")
)
