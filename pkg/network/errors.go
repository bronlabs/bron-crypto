package network

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument reports a malformed or unsupported argument.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrFailed reports a generic network-layer failure.
	ErrFailed = errs.New("failed")
	// ErrReceiveBufferFull reports that the router's undelivered-message buffer reached its capacity.
	ErrReceiveBufferFull = errs.New("receive buffer full")
	// ErrDuplicateMessage reports conflicting messages from one sender under one correlation ID.
	ErrDuplicateMessage = errs.New("duplicate message")
	// ErrRouterClosed reports that the router was closed while receiving.
	ErrRouterClosed = errs.New("router closed")
)
