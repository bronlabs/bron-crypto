package dkls23

import "github.com/bronlabs/errs-go/pkg/errs"

var (
	// ErrFailed represents failed.
	ErrFailed = errs.New("failed")
	// ErrNil represents nil.
	ErrNil = errs.New("nil")
	// ErrVerificationFailed represents verification failed.
	ErrVerificationFailed = errs.New("verification failed")
	// ErrSerialisation represents serialisation error.
	ErrSerialisation = errs.New("serialisation error")
	// ErrHashing represents hashing failed.
	ErrHashing = errs.New("hashing failed")
)
