package bls

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	// ErrInvalidArgument indicates missing, nil, or inconsistent inputs.
	ErrInvalidArgument = errs2.New("invalid argument")
	// ErrFailed indicates a general failure during protocol execution.
	ErrFailed = errs2.New("failed")
	// ErrVerificationFailed signals a failed signature or proof verification.
	ErrVerificationFailed = errs2.New("verification failed")
	// ErrNotSupported indicates an unsupported algorithm or variant.
	ErrNotSupported = errs2.New("not supported")
	// ErrInvalidSubGroup indicates an element is not in the correct subgroup.
	ErrInvalidSubGroup = errs2.New("invalid subgroup")
)
