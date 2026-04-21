package bls

import "github.com/bronlabs/bron-crypto/pkg/signatures"

var (
	// ErrInvalidArgument is kept for compatibility; prefer signatures.ErrInvalidArgument.
	ErrInvalidArgument = signatures.ErrInvalidArgument
	// ErrFailed is kept for compatibility; prefer signatures.ErrFailed.
	ErrFailed = signatures.ErrFailed
	// ErrVerificationFailed is kept for compatibility; prefer signatures.ErrVerificationFailed.
	ErrVerificationFailed = signatures.ErrVerificationFailed
	// ErrNotSupported is kept for compatibility; prefer signatures.ErrNotSupported.
	ErrNotSupported = signatures.ErrNotSupported
	// ErrInvalidSubGroup is kept for compatibility; prefer signatures.ErrInvalidSubGroup.
	ErrInvalidSubGroup = signatures.ErrInvalidSubGroup
)
