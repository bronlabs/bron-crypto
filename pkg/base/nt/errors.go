package nt

import "github.com/bronlabs/errs-go/errs"

var (
	ErrInvalidArgument = errs.New("invalid argument")
	ErrIsNil           = errs.New("is nil")
)
