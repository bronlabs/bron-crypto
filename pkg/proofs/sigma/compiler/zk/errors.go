package zk

import "github.com/bronlabs/errs-go/pkg/errs"

var (
	ErrNil          = errs.New("nil")
	ErrInvalid      = errs.New("invalid")
	ErrFailed       = errs.New("failed")
	ErrVerification = errs.New("verification failed")
	ErrRound        = errs.New("invalid round")
)
