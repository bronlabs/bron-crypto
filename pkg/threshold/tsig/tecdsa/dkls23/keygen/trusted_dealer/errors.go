package trusted_dealer

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	// ErrFailed represents failed.
	ErrFailed = errs2.New("failed")
	// ErrRandomSample represents random sample failed.
	ErrRandomSample = errs2.New("random sample failed")
)
