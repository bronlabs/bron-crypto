package network

import "github.com/bronlabs/errs-go/errs"

var (
	ErrInvalidArgument   = errs.New("invalid argument")
	ErrFailed            = errs.New("failed")
	ErrReceiveBufferFull = errs.New("receive buffer full")
	ErrDuplicateMessage  = errs.New("duplicate message")
)
