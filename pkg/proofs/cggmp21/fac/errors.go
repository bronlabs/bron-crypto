package fac

import "github.com/bronlabs/bron-crypto/pkg/proofs"

var (
	// ErrInvalidArgument indicates that an input is nil or malformed.
	ErrInvalidArgument = proofs.ErrInvalidArgument
	// ErrValidationFailed indicates that the statement or witness is invalid.
	ErrValidationFailed = proofs.ErrValidationFailed
	// ErrVerificationFailed indicates that a transcript failed verification.
	ErrVerificationFailed = proofs.ErrVerificationFailed
)
