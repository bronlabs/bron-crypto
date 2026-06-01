package blummod

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument indicates missing or inconsistent protocol inputs.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrValidationFailed signals malformed or inconsistent protocol inputs.
	ErrValidationFailed = errs.New("validation failed")
	// ErrVerificationFailed signals failed proof verification.
	ErrVerificationFailed = errs.New("verification failed")
	// ErrUnsupported signals protocol functionality that this implementation cannot expose.
	ErrUnsupported = errs.New("unsupported")
	// ErrFailed indicates a general failure during protocol execution.
	ErrFailed = errs.New("failed")
)
