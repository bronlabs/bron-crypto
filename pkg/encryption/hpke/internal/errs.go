package internal

import "github.com/bronlabs/errs-go/pkg/errs"

var (
	ErrNotSupported     = errs.New("not supported")
	ErrInvalidLength    = errs.New("invalid length")
	ErrInvalidArgument  = errs.New("invalid argument")
	ErrInvalidPublicKey = errs.New("invalid public key")
	ErrInvalidNonce     = errs.New("invalid nonce")
)
