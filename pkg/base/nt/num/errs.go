package num

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	ErrInexactDivision = errs2.New("inexact division")
	ErrUndefined       = errs2.New("operation is undefined")
	ErrOutOfRange      = errs2.New("value is out of range")
	ErrUnequalModuli   = errs2.New("moduli are unequal")
	ErrIsNil           = errs2.New("value must not be nil")
)
