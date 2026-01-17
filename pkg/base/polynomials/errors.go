package polynomials

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	ErrValidation            = errs2.New("invalid")
	ErrDivisionByZero        = errs2.New("division by zero")
	ErrOperationNotSupported = errs2.New("operation not supported")
	ErrLengthMismatch        = errs2.New("input length mismatch")
	ErrFailed                = errs2.New("internal error")
	ErrSerialisationFailed   = errs2.New("serialisation failed")
)
