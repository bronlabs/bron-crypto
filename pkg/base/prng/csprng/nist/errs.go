package nist

import "github.com/bronlabs/errs-go/pkg/errs"

var (
	ErrInvalidArgument = errs.New("invalid argument")
	ErrInvalidKey      = errs.New("invalid key")
	ErrInvalidEntropy  = errs.New("invalid entropy")
	ErrInvalidNonce    = errs.New("invalid nonce")
)
