package additive

import "github.com/bronlabs/errs-go/pkg/errs"

var (
	ErrIsNil      = errs.New("is nil")
	ErrMembership = errs.New("membership error")
	ErrFailed     = errs.New("failed")
)
