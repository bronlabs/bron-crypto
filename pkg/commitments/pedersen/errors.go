package pedersen

import "github.com/bronlabs/bron-crypto/pkg/base/errs2"

var (
	ErrInvalidArgument = errs2.New("invalid arguments")
	ErrFailed          = errs2.New("failed")
	ErrSerialisation   = errs2.New("serialisation/deserialisation failed")
)
