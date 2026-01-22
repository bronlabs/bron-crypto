package sharing

import "github.com/bronlabs/errs-go/pkg/errs"

var (
	ErrIsNil      = errs.New("is nil")
	ErrValue      = errs.New("invalid value")
	ErrMembership = errs.New("membership error")
)
