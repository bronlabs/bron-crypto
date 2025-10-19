package softspoken

import (
	"hash"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

const (
	Kappa = base.ComputationalSecurityBits
	// Sigma should really be StatisticalSecurity but since we need (Xi * L) to be a multiple of Sigma,
	// we can just use base.ComputationalSecurity which is bigger anyway.
	Sigma      = base.ComputationalSecurityBits
	SigmaBytes = (Sigma + 7) / 8
)

type Suite struct {
	ot.DefaultSuite

	hashFunc func() hash.Hash
}

func NewSuite(xi, l int, hashFunc func() hash.Hash) (*Suite, error) {
	defaultSuite, err := ot.NewDefaultSuite(xi, l)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create default OT suite")
	}
	if (xi % 8) != 0 {
		return nil, errs.NewValidation("invalid xi")
	}
	if ((xi * l) % Sigma) != 0 {
		return nil, errs.NewValidation("invalid xi or l; (xi * l) must be multiple of %d for consistency check", Sigma)
	}

	s := &Suite{*defaultSuite, hashFunc}
	return s, nil
}

type SenderOutput struct {
	ot.SenderOutput[[]byte]
}

func (so *SenderOutput) InferredMessageBytesLen() int {
	if len(so.Messages) == 0 {
		return 0
	}
	if len(so.Messages[0][0]) == 0 || len(so.Messages[0][1]) == 0 {
		return 0
	}
	l := len(so.Messages[0][0][0])
	for _, messages := range so.Messages {
		for _, message := range messages[0] {
			if len(message) != l {
				return 0
			}
		}
		for _, message := range messages[1] {
			if len(message) != l {
				return 0
			}
		}
	}
	return l
}

type ReceiverOutput struct {
	ot.ReceiverOutput[[]byte]
}

func (ro *ReceiverOutput) InferredMessageBytesLen() int {
	if len(ro.Messages) == 0 {
		return 0
	}
	if len(ro.Messages[0]) == 0 {
		return 0
	}
	l := len(ro.Messages[0][0])
	for _, messages := range ro.Messages {
		for _, message := range messages {
			if len(message) != l {
				return 0
			}
		}
	}
	return l
}
