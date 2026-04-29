package signatures

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidArgument indicates missing, nil, or inconsistent inputs.
	// This is the canonical sentinel for signature packages; prefer signatures.ErrInvalidArgument.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrFailed indicates a general failure during protocol execution.
	// This is the canonical sentinel for signature packages; prefer signatures.ErrFailed.
	ErrFailed = errs.New("failed")
	// ErrVerificationFailed signals a failed signature or proof verification.
	// This is the canonical sentinel for signature packages; prefer signatures.ErrVerificationFailed.
	ErrVerificationFailed = errs.New("verification failed")
	// ErrSerialization indicates a serialisation or deserialization error.
	// This is the canonical sentinel for signature packages; prefer signatures.ErrSerialization.
	ErrSerialization = errs.New("serialisation error")
	// ErrNotSupported indicates an unsupported algorithm or variant.
	// This is the canonical sentinel for signature packages; prefer signatures.ErrNotSupported.
	ErrNotSupported = errs.New("not supported")
	// ErrInvalidSubGroup indicates an element is not in the correct subgroup.
	// This is the canonical sentinel for signature packages; prefer signatures.ErrInvalidSubGroup.
	ErrInvalidSubGroup = errs.New("invalid subgroup")
	// ErrInvalidDerivation indicates invalid child-key derivation inputs or outputs.
	// This is the canonical sentinel for signature packages; prefer signatures.ErrInvalidDerivation.
	ErrInvalidDerivation = errs.New("invalid derivation")
)
