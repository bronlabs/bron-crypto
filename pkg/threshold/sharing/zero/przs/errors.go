package przs

import "github.com/bronlabs/errs-go/pkg/errs"

var (
	// ErrInvalidArgument indicates missing or inconsistent inputs.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrFailed captures non-recoverable protocol failures.
	ErrFailed = errs.New("failed")
)
