package sharing

import (
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/errs-go/errs"
)

var (
	// ErrIsNil indicates a required value was nil.
	ErrIsNil = accessstructures.ErrIsNil
	// ErrValue indicates an invalid value.
	ErrValue = accessstructures.ErrValue
	// ErrMembership indicates an invalid shareholder membership relation.
	ErrMembership = accessstructures.ErrMembership
	// ErrFailed indicates an operation failed.
	ErrFailed = errs.New("failed")
	// ErrArgument indicates invalid function arguments.
	ErrArgument = errs.New("invalid argument")
	// ErrVerification indicates share or proof verification failed.
	ErrVerification = errs.New("verification failed")
	// ErrType indicates a type mismatch.
	ErrType = errs.New("type error")
	// ErrUnauthorized indicates an unauthorised operation.
	ErrUnauthorized = errs.New("unauthorised")
	// ErrIsZero indicates a forbidden zero value.
	ErrIsZero = errs.New("is zero")
)
