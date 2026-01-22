package sigma

import "github.com/bronlabs/errs-go/pkg/errs"

var (
	// ErrInvalidArgument indicates missing or inconsistent inputs.
	ErrInvalidArgument = errs.New("invalid argument")
	// ErrRound is returned when rounds are invoked out of order.
	ErrRound = errs.New("invalid round")
)
