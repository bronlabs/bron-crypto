package algebrautils

import "github.com/bronlabs/errs-go/errs"

var (
	ErrIsNil           = errs.New("argument is nil")
	ErrInvalidArgument = errs.New("invalid argument")
)
