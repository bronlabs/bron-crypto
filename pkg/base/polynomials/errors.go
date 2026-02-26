package polynomials

import "github.com/bronlabs/errs-go/errs"

// Sentinel errors returned by functions in the polynomials package.
var (
	// ErrValidation indicates invalid input such as nil arguments, wrong arity, or negative degree.
	ErrValidation = errs.New("invalid")
	// ErrDivisionByZero indicates an attempted Euclidean division by the zero polynomial.
	ErrDivisionByZero = errs.New("division by zero")
	// ErrOperationNotSupported indicates an algebraic operation that is not defined
	// for polynomials (e.g. multiplicative inverse).
	ErrOperationNotSupported = errs.New("operation not supported")
	// ErrLengthMismatch indicates that input slices have incompatible lengths.
	ErrLengthMismatch = errs.New("input length mismatch")
	// ErrFailed indicates an unexpected internal error.
	ErrFailed = errs.New("internal error")
	// ErrSerialisationFailed indicates a CBOR marshal/unmarshal failure.
	ErrSerialisationFailed = errs.New("serialisation failed")
)
