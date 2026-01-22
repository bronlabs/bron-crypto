package shamir

import "github.com/bronlabs/errs-go/pkg/errs"

var (
	ErrIsNil      = errs.New("is nil")
	ErrValue      = errs.New("invalid value")
	ErrMembership = errs.New("membership error")
	ErrType       = errs.New("type error")
	ErrFailed     = errs.New("failed")
)
