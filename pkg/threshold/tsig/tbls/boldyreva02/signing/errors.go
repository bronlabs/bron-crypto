package signing

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	// ErrInvalidArgument indicates an invalid argument was provided.
	ErrInvalidArgument = errs2.New("invalid argument")

	// ErrFailed indicates a general operation failure.
	ErrFailed = errs2.New("failed")

	// ErrRound indicates an operation was called in the wrong protocol round.
	ErrRound = errs2.New("invalid round")

	// ErrVerificationFailed indicates signature or proof verification failed.
	ErrVerificationFailed = errs2.New("verification failed")
)
