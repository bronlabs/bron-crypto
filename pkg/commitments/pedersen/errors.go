package pedersen

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/commitments"
)

var (
	ErrIsNil           = commitments.ErrIsNil
	ErrIsIdentity      = errs.New("is identity")
	ErrInvalidArgument = commitments.ErrInvalidArgument
)
