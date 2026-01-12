package vanilla

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	// ErrInvalidArgument indicates missing, nil, or inconsistent inputs.
	ErrInvalidArgument = errs2.New("invalid argument")
)
