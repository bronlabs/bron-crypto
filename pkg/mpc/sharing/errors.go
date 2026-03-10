package sharing

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/internal"
)

var (
	// ErrIsNil indicates a required value was nil.
	ErrIsNil = internal.ErrIsNil
	// ErrValue indicates an invalid value.
	ErrValue = internal.ErrValue
	// ErrMembership indicates an invalid shareholder membership relation.
	ErrMembership = internal.ErrMembership
	// ErrFailed indicates an operation failed.
	ErrFailed = internal.ErrFailed
	// ErrArgument indicates invalid function arguments.
	ErrArgument = errs.New("invalid argument")
	// ErrVerification indicates share or proof verification failed.
	ErrVerification = errs.New("verification failed")
	// ErrType indicates a type mismatch.
	ErrType = internal.ErrType
	// ErrUnauthorized indicates an unauthorised operation.
	ErrUnauthorized = errs.New("unauthorised")
	// ErrIsZero indicates a forbidden zero value.
	ErrIsZero = errs.New("is zero")
)
