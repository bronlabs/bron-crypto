package polynomials

import "github.com/bronlabs/errs-go/errs"

var (
	ErrValidation            = errs.New("invalid")
	ErrDivisionByZero        = errs.New("division by zero")
	ErrOperationNotSupported = errs.New("operation not supported")
	ErrLengthMismatch        = errs.New("input length mismatch")
	ErrFailed                = errs.New("internal error")
	ErrSerialisationFailed   = errs.New("serialisation failed")
)
