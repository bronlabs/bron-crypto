package nt

import "github.com/bronlabs/bron-crypto/pkg/base/nt/internal/primegen"

var (
	// ErrInvalidArgument reports a structurally invalid request: a bit length
	// or key length outside the supported range, or an odd keyLen.
	ErrInvalidArgument = primegen.ErrInvalidArgument
	// ErrIsNil reports a nil structure or PRNG argument.
	ErrIsNil = primegen.ErrIsNil
	// ErrFailed reports a violated internal invariant.
	ErrFailed = primegen.ErrFailed
)
