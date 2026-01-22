package bip340

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument indicates missing, nil, or inconsistent inputs.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrFailed indicates a general failure during protocol execution.
	ErrFailed = errs.New("failed")
	// ErrVerificationFailed signals a failed signature verification.
	ErrVerificationFailed = errs.New("verification failed")
	// ErrSerialization indicates a serialisation or deserialization error.
	ErrSerialization = errs.New("serialisation error")
)
