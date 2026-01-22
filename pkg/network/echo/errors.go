package echo

import "github.com/bronlabs/errs-go/pkg/errs"

var (
	ErrInvalidArgument = errs.New("invalid argument")
	ErrFailed          = errs.New("failed")
)
