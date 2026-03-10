package hierarchical

import (
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
)
