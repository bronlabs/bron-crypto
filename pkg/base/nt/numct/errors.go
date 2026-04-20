package numct

import (
	"github.com/bronlabs/errs-go/errs"
)

var (
	ErrInvalidArgument = errs.New("invalid argument")
	ErrDeserialisation = errs.New("deserialisation failed")
)
