package dkg

import "github.com/bronlabs/errs-go/errs"

var (
	// ErrRound represents invalid round.
	ErrRound = errs.New("invalid round")
	// ErrFailed represents failed.
	ErrFailed = errs.New("failed")
	// ErrNil represents nil.
	ErrNil = errs.New("nil")
	// ErrRandomSample represents random sample failed.
	ErrRandomSample = errs.New("random sample failed")
)
