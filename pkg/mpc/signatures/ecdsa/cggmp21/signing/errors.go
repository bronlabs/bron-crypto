package signing

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrInvalidRound is returned when a signing round is called out of order.
	ErrInvalidRound = errs.New("invalid round")
	// ErrFailed is returned when an internal signing invariant is not satisfied.
	ErrFailed = errs.New("failed")
)
