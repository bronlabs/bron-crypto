package gennaro

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	// ErrInvalidArgument indicates incorrect or missing inputs.
	ErrInvalidArgument = errs2.New("invalid argument")
	// ErrFailed captures non-recoverable protocol failures.
	ErrFailed = errs2.New("failed")
	// ErrRound signals that a round was invoked out of order.
	ErrRound = errs2.New("invalid round")
)
