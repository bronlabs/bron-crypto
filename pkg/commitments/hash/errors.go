package hash_comm

import "github.com/bronlabs/errs-go/errs"

var (
	ErrInvalidArgument = errs.New("invalid argument")
	ErrFailed          = errs.New("failed")
)
