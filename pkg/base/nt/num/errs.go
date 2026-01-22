package num

import "github.com/bronlabs/errs-go/errs"

var (
	ErrInexactDivision = errs.New("inexact division")
	ErrUndefined       = errs.New("operation is undefined")
	ErrOutOfRange      = errs.New("value is out of range")
	ErrUnequalModuli   = errs.New("moduli are unequal")
	ErrIsNil           = errs.New("value must not be nil")
	ErrDivisionByZero  = errs.New("division by zero")
)
