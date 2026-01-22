package mina

import "github.com/bronlabs/errs-go/pkg/errs"

var (
	// ErrInvalidArgument indicates missing, nil, or inconsistent inputs.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrVerificationFailed signals a failed signature verification.
	ErrVerificationFailed = errs.New("verification failed")
	// ErrSerialization indicates a serialisation or deserialization error.
	ErrSerialization = errs.New("serialisation error")
)
