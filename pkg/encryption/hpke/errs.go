package hpke

import "github.com/bronlabs/errs-go/pkg/errs"

var (
	ErrInvalidArgument = errs.New("invalid argument")
	ErrInvalidLength   = errs.New("invalid length")
	ErrNotSupported    = errs.New("not supported")
)
