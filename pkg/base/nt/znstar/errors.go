package znstar

import "github.com/bronlabs/errs-go/errs"

var (
	ErrIsNil  = errs.New("is nil")
	ErrFailed = errs.New("failed")
	ErrValue  = errs.New("invalid value")
)
