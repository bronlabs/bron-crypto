package ot

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	ErrInvalidArgument = errs2.New("invalid argument")
	ErrFailed          = errs2.New("failed")
	ErrSerialisation   = errs2.New("serialisation failed")
	ErrRound           = errs2.New("invalid round")
	ErrVerification    = errs2.New("verification failed")
)
