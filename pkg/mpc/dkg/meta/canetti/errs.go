package canetti

import "github.com/bronlabs/errs-go/errs"

var (
	ErrInvalidArgument    = errs.New("invalid argument")
	ErrVerificationFailed = errs.New("verification failed")
	ErrRound              = errs.New("invalid round")
)
