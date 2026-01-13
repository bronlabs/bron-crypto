package sharing

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	ErrIsNil      = errs2.New("is nil")
	ErrValue      = errs2.New("invalid value")
	ErrMembership = errs2.New("membership error")
)
