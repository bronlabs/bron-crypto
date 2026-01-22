package signing

import "github.com/bronlabs/errs-go/pkg/errs"

var (
	// ErrInvalidArgument indicates missing or inconsistent inputs.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrRound is returned when rounds are invoked out of order.
	ErrRound = errs.New("invalid round")
	// ErrMissing indicates required data is missing.
	ErrMissing = errs.New("missing")
	// ErrValidationFailed signals malformed or inconsistent protocol inputs.
	ErrValidationFailed = errs.New("validation failed")
	// ErrVerificationFailed signals a failed proof verification.
	ErrVerificationFailed = errs.New("verification failed")
	// ErrFailed indicates a general failure during protocol execution.
	ErrFailed = errs.New("failed")
)
