package przs

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	// ErrInvalidArgument indicates missing or inconsistent inputs.
	ErrInvalidArgument = errs2.New("invalid argument")
	// ErrFailed captures non-recoverable protocol failures.
	ErrFailed = errs2.New("failed")
)
