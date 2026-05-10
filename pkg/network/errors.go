package network

import "github.com/bronlabs/errs-go/errs"

var (
	ErrInvalidArgument       = errs.New("invalid argument")
	ErrFailed                = errs.New("failed")
	ErrFrameTooLarge         = errs.New("frame too large")
	ErrPayloadTooLarge       = errs.New("payload too large")
	ErrCorrelationIDTooLarge = errs.New("correlation id too large")
	ErrReceiveBufferFull     = errs.New("receive buffer full")
	ErrDuplicateMessage      = errs.New("duplicate message")
)
