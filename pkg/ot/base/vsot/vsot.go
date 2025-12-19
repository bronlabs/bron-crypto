package vsot

import (
	"hash"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

// SenderOutput carries the sender's ROT outputs for VSOT.
type SenderOutput struct {
	ot.SenderOutput[[]byte] `cbor:"output"`
}

// InferredMessageBytesLen infers the byte length of messages, returning 0 on inconsistency.
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
	ot.ReceiverOutput[[]byte] `cbor:"output"`
}

// InferredMessageBytesLen infers the byte length of messages, returning 0 on inconsistency.
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

type Suite[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ot.DefaultSuite

	curve    curves.Curve[P, B, S]
	field    algebra.PrimeField[S]
	hashFunc func() hash.Hash
}

// NewSuite configures VSOT over the given curve with batch size xi and block length l.
func NewSuite[P curves.Point[P, B, S], B algebra.FieldElement[B], S algebra.PrimeFieldElement[S]](xi, l int, curve curves.Curve[P, B, S], hashFunc func() hash.Hash) (*Suite[P, B, S], error) {
	if hashFunc == nil {
		return nil, ot.ErrInvalidArgument.WithMessage("invalid hash func")
	}
	if (xi % 8) != 0 {
		return nil, ot.ErrInvalidArgument.WithMessage("invalid xi")
	}
	field, ok := curve.ScalarStructure().(algebra.PrimeField[S])
	if !ok {
		return nil, ot.ErrFailed.WithMessage("invalid curve scalar structure")
	}

	defaultSuite, err := ot.NewDefaultSuite(xi, l)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to create default suite")
	}
	s := &Suite[P, B, S]{
		DefaultSuite: *defaultSuite,
		curve:        curve,
		field:        field,
		hashFunc:     hashFunc,
	}

	return s, nil
}

// Curve returns the curve used by the suite.
func (s *Suite[P, B, S]) Curve() curves.Curve[P, B, S] {
	return s.curve
}

// Field returns the prime field used for scalars.
func (s *Suite[P, B, S]) Field() algebra.PrimeField[S] {
	return s.field
}

// HashFunc returns the hash function used in the protocol.
func (s *Suite[P, B, S]) HashFunc() func() hash.Hash {
	return s.hashFunc
}
