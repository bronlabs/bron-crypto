package znstar

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	ErrIsNil  = errs2.New("is nil")
	ErrFailed = errs2.New("failed")
	ErrValue  = errs2.New("invalid value")
)
