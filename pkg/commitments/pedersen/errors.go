package pedersen

import "github.com/bronlabs/errs-go/errs"

var (
	ErrInvalidArgument = errs.New("invalid arguments")
	ErrFailed          = errs.New("failed")
	ErrSerialisation   = errs.New("serialisation/deserialisation failed")
)
