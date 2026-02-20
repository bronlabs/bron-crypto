package mat

import "github.com/bronlabs/errs-go/errs"

// Sentinel errors for matrix operations.
var (
	ErrOutOfBounds = errs.New("index out of bounds")
	ErrDimension   = errs.New("dimension error")
	ErrFailed      = errs.New("operation failed")
)
