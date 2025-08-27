package softspoken

import (
	"hash"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

const (
	Kappa      = base.ComputationalSecurity
	Sigma      = base.StatisticalSecurity
	SigmaBytes = (Sigma + 7) / 8
)

type Suite struct {
	ot.DefaultSuite
	hashFunc func() hash.Hash
}

func NewSuite(xi, l int, hashFunc func() hash.Hash) (*Suite, error) {
	defaultSuite, err := ot.NewDefaultSuite(xi, l)
	if err != nil {
		return nil, err
	}
	if (xi % 8) != 0 {
		return nil, errs.NewValidation("invalid xi")
	}

	s := &Suite{*defaultSuite, hashFunc}
	return s, nil
}

type ReceiverOutput = ot.ReceiverOutput[[]byte]
type SenderOutput = ot.SenderOutput[[]byte]
