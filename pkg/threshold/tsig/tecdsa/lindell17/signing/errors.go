package signing

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	// ErrInvalidArgument indicates missing or inconsistent inputs.
	ErrInvalidArgument = errs2.New("invalid argument")
	// ErrRound is returned when rounds are invoked out of order.
	ErrRound = errs2.New("invalid round")
	// ErrMissing indicates required data is missing.
	ErrMissing = errs2.New("missing")
	// ErrValidationFailed signals malformed or inconsistent protocol inputs.
	ErrValidationFailed = errs2.New("validation failed")
	// ErrVerificationFailed signals a failed proof verification.
	ErrVerificationFailed = errs2.New("verification failed")
	// ErrFailed indicates a general failure during protocol execution.
	ErrFailed = errs2.New("failed")
)
