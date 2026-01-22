package gennaro

import "github.com/bronlabs/errs-go/pkg/errs"

var (
	// ErrInvalidArgument indicates incorrect or missing inputs.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrFailed captures non-recoverable protocol failures.
	ErrFailed = errs.New("failed")
	// ErrRound signals that a round was invoked out of order.
	ErrRound = errs.New("invalid round")
)
