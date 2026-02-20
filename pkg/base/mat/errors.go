package mat

import "github.com/bronlabs/errs-go/errs"

var (
	ErrOutOfBounds       = errs.New("index out of bounds")
	ErrDimensionMismatch = errs.New("dimension mismatch")
	ErrFailed            = errs.New("operation failed")
)
