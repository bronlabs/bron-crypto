package hpke

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	ErrInvalidArgument = errs2.New("invalid argument")
	ErrInvalidLength   = errs2.New("invalid length")
	ErrNotSupported    = errs2.New("not supported")
)
