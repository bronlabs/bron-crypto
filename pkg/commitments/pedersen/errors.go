package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/errs-go/errs"
)

var (
	ErrVerificationFailed = commitments.ErrVerificationFailed
	ErrIsNil              = commitments.ErrIsNil
	ErrIsIdentity         = errs.New("is identity")
	ErrInvalidArgument    = commitments.ErrInvalidArgument
)
