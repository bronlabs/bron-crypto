package dkg

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	// ErrRound represents invalid round.
	ErrRound = errs2.New("invalid round")
	// ErrFailed represents failed.
	ErrFailed = errs2.New("failed")
	// ErrNil represents nil.
	ErrNil = errs2.New("nil")
	// ErrRandomSample represents random sample failed.
	ErrRandomSample = errs2.New("random sample failed")
)
