package canetti

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument is returned when a constructor or round receives invalid input.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrVerificationFailed is returned when a message fails local validation.
	ErrVerificationFailed = errs.New("verification failed")
	// ErrRound is returned when a round method is called out of order.
	ErrRound = errs.New("invalid round")
)
