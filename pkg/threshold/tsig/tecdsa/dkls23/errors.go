package dkls23

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	// ErrFailed represents failed.
	ErrFailed = errs2.New("failed")
	// ErrNil represents nil.
	ErrNil = errs2.New("nil")
	// ErrVerificationFailed represents verification failed.
	ErrVerificationFailed = errs2.New("verification failed")
	// ErrSerialisation represents serialisation error.
	ErrSerialisation = errs2.New("serialisation error")
	// ErrHashing represents hashing failed.
	ErrHashing = errs2.New("hashing failed")
)
