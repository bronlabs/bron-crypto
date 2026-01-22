package trusted_dealer

import "github.com/bronlabs/errs-go/pkg/errs"

var (
	// ErrFailed represents failed.
	ErrFailed = errs.New("failed")
	// ErrRandomSample represents random sample failed.
	ErrRandomSample = errs.New("random sample failed")
)
