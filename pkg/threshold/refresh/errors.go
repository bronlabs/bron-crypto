package refresh

import "github.com/bronlabs/errs-go/pkg/errs"

var (
	// ErrInvalidArgument indicates missing or inconsistent inputs.
	ErrInvalidArgument = errs.New("invalid argument")
)
