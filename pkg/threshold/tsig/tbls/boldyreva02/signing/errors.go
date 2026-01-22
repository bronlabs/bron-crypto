package signing

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument indicates an invalid argument was provided.
	ErrInvalidArgument = errs.New("invalid argument")

	// ErrFailed indicates a general operation failure.
	ErrFailed = errs.New("failed")

	// ErrRound indicates an operation was called in the wrong protocol round.
	ErrRound = errs.New("invalid round")

	// ErrVerificationFailed indicates signature or proof verification failed.
	ErrVerificationFailed = errs.New("verification failed")
)
