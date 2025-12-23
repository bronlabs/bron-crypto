package lindell17

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	// ErrInvalidArgument indicates missing or inconsistent inputs.
	ErrInvalidArgument = errs2.New("invalid argument")
	// ErrFailed indicates a general failure during protocol execution.
	ErrFailed = errs2.New("failed")
)
