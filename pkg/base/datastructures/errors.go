package datastructures

import "github.com/bronlabs/errs-go/pkg/errs"

// ErrInvalidSize is returned when an operation encounters a size mismatch or invalid size constraint.
var ErrInvalidSize = errs.New("invalid size")
