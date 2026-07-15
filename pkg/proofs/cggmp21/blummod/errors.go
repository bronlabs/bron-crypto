package blummod

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/proofs"
)

var (
	// ErrInvalidArgument indicates missing or inconsistent protocol inputs.
	ErrInvalidArgument = proofs.ErrInvalidArgument
	// ErrValidationFailed signals malformed or inconsistent protocol inputs.
	ErrValidationFailed = proofs.ErrValidationFailed
	// ErrVerificationFailed signals failed proof verification.
	ErrVerificationFailed = proofs.ErrVerificationFailed
	// ErrUnsupported signals protocol functionality that this implementation cannot expose.
	ErrUnsupported = errs.New("unsupported")
	// ErrFailed indicates a general failure during protocol execution.
	ErrFailed = proofs.ErrFailed
)
