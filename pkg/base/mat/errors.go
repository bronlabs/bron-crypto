package mat

import "github.com/bronlabs/errs-go/errs"

var (
	ErrOutOfBounds = errs.New("index out of bounds")
	ErrDimension   = errs.New("dimension error")
	ErrFailed      = errs.New("operation failed")
)
