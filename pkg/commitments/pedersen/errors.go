package pedersen

import "github.com/bronlabs/errs-go/pkg/errs"

var (
	ErrInvalidArgument = errs.New("invalid arguments")
	ErrFailed          = errs.New("failed")
	ErrSerialisation   = errs.New("serialisation/deserialisation failed")
)
