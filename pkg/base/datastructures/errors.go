package datastructures

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

// ErrInvalidSize is returned when an operation encounters a size mismatch or invalid size constraint.
var ErrInvalidSize = errs2.New("invalid size")
