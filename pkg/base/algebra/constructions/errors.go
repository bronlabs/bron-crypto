package constructions

import "github.com/bronlabs/errs-go/errs"

var (
	ErrInvalidArgument = errs.New("invalid argument")
	ErrInvalidType     = errs.New("invalid type")
)
