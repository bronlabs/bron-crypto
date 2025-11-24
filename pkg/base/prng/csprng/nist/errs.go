package nist

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	ErrInvalidArgument = errs2.New("invalid argument")
	ErrInvalidKey      = errs2.New("invalid key")
	ErrInvalidEntropy  = errs2.New("invalid entropy")
	ErrInvalidNonce    = errs2.New("invalid nonce")
)
