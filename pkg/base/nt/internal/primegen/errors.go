package primegen

import "github.com/bronlabs/errs-go/errs"

// The nt package validates arguments before calling into this package and
// reports its own sentinels; the sentinels here back the defensive
// re-validation inside this package and internal invariant checks. They are
// deliberately distinct values from nt's (importing nt here would be a
// cycle) — callers outside nt never see them unwrapped.
var (
	// ErrInvalidArgument reports a structurally invalid request: bit length
	// below MinBits, a malformed lower bound, a bad class, or missing
	// Miller-Rabin round counts.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrIsNil reports a nil PRNG.
	ErrIsNil = errs.New("is nil")
	// ErrFailed reports a violated internal invariant.
	ErrFailed = errs.New("operation failed")
)
