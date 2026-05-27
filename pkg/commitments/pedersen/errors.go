package pedersen

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/commitments"
)

var (
	// ErrIsNil indicates a required argument (generator, scalar, prng, …) was nil.
	ErrIsNil = commitments.ErrIsNil
	// ErrIsIdentity indicates a generator was the group identity element, which
	// cannot anchor a binding commitment key.
	ErrIsIdentity = errs.New("is identity")
	// ErrInvalidArgument indicates an argument failed validation, e.g. non-distinct
	// generators or a trapdoor value of zero or one.
	ErrInvalidArgument = commitments.ErrInvalidArgument
)
