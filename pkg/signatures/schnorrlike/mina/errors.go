package mina

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	// ErrInvalidArgument indicates missing, nil, or inconsistent inputs.
	ErrInvalidArgument = errs2.New("invalid argument")
	// ErrVerificationFailed signals a failed signature verification.
	ErrVerificationFailed = errs2.New("verification failed")
	// ErrSerialization indicates a serialisation or deserialization error.
	ErrSerialization = errs2.New("serialisation error")
)
