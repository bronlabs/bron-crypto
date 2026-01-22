package vanilla

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument indicates missing, nil, or inconsistent inputs.
	ErrInvalidArgument = errs.New("invalid argument")
)
