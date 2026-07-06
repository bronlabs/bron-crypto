package enc

import (
	"github.com/bronlabs/bron-crypto/pkg/proofs"
)

var (
	// ErrInvalidArgument indicates missing or inconsistent protocol inputs.
	ErrInvalidArgument = proofs.ErrInvalidArgument
	// ErrValidationFailed indicates that a statement/witness pair is malformed or inconsistent.
	ErrValidationFailed = proofs.ErrValidationFailed
	// ErrVerificationFailed indicates a failed sigma-protocol verification.
	ErrVerificationFailed = proofs.ErrVerificationFailed
)
