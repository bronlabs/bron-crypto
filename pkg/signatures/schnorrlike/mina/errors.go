package mina

import "github.com/bronlabs/bron-crypto/pkg/signatures"

var (
	// ErrInvalidArgument is kept for compatibility; prefer signatures.ErrInvalidArgument.
	ErrInvalidArgument = signatures.ErrInvalidArgument
	// ErrVerificationFailed is kept for compatibility; prefer signatures.ErrVerificationFailed.
	ErrVerificationFailed = signatures.ErrVerificationFailed
	// ErrSerialization is kept for compatibility; prefer signatures.ErrSerialization.
	ErrSerialization = signatures.ErrSerialization
)
