package bls

import "github.com/bronlabs/errs-go/pkg/errs"

var (
	// ErrInvalidArgument indicates missing, nil, or inconsistent inputs.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrFailed indicates a general failure during protocol execution.
	ErrFailed = errs.New("failed")
	// ErrVerificationFailed signals a failed signature or proof verification.
	ErrVerificationFailed = errs.New("verification failed")
	// ErrNotSupported indicates an unsupported algorithm or variant.
	ErrNotSupported = errs.New("not supported")
	// ErrInvalidSubGroup indicates an element is not in the correct subgroup.
	ErrInvalidSubGroup = errs.New("invalid subgroup")
)
