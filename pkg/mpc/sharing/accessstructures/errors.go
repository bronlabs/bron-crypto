package accessstructures

import (
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/internal"
	"github.com/bronlabs/errs-go/errs"
)

var (
	// ErrIsNil indicates a required value was nil.
	ErrIsNil = internal.ErrIsNil
	// ErrValue indicates an invalid value.
	ErrValue = errs.New("invalid value")
	// ErrMembership indicates an invalid shareholder membership relation.
	ErrMembership = errs.New("membership error")
)
