package softspoken

import (
	"hash"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

const (
	// Kappa is the computational security parameter and number of seed OTs.
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

// NewSuite configures SoftSpokenOT for batch size xi, block length l, and hash function.
func NewSuite(xi, l int, hashFunc func() hash.Hash) (*Suite, error) {
	defaultSuite, err := ot.NewDefaultSuite(xi, l)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to create default OT suite")
	}
	if (xi % 8) != 0 {
		return nil, ot.ErrInvalidArgument.WithMessage("invalid xi")
	}
	if ((xi * l) % Sigma) != 0 {
		return nil, ot.ErrInvalidArgument.WithMessage("invalid xi or l; (xi * l) must be multiple of %d for consistency check", Sigma)
	}

	s := &Suite{*defaultSuite, hashFunc}
	return s, nil
}

// SenderOutput holds the sender's SoftSpoken outputs.
type SenderOutput struct {
	ot.SenderOutput[[]byte]
}

// InferredMessageBytesLen infers the message byte length, returning 0 on inconsistency.
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

// InferredMessageBytesLen infers the message byte length, returning 0 on inconsistency.
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
