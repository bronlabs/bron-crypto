package internal

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	ErrNotSupported     = errs2.New("not supported")
	ErrInvalidLength    = errs2.New("invalid length")
	ErrInvalidArgument  = errs2.New("invalid argument")
	ErrInvalidPublicKey = errs2.New("invalid public key")
	ErrInvalidNonce     = errs2.New("invalid nonce")
)
