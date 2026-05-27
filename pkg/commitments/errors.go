package commitments

import (
	"github.com/bronlabs/errs-go/errs"
)

var (
	// ErrVerificationFailed indicates an opening did not match: the commitment
	// recomputed by Open from (message, witness) differs from the one supplied.
	ErrVerificationFailed = errs.New("verification failed")
	// ErrIsNil indicates a required argument (key, message, witness, commitment, or
	// prng) was nil.
	ErrIsNil = errs.New("is nil")
	// ErrSubGroupMembership indicates a value is not in the expected subgroup; for
	// group-based schemes this is a validation / deserialization trust-boundary
	// failure that can otherwise undermine binding.
	ErrSubGroupMembership = errs.New("not in subgroup")
	// ErrInvalidArgument indicates an argument failed a scheme-specific validity
	// check (e.g. non-distinct or identity generators, an out-of-range parameter).
	ErrInvalidArgument = errs.New("invalid argument")
)
