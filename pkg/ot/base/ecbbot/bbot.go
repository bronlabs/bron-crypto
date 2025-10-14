package ecbbot

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
	"golang.org/x/crypto/blake2b"
)

type Suite[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	ot.DefaultSuite
	group       algebra.PrimeGroup[G, S]
	scalarField algebra.PrimeField[S]
}

func NewSuite[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](xi, l int, group algebra.PrimeGroup[G, S]) (*Suite[G, S], error) {
	if group == nil {
		return nil, errs.NewValidation("invalid group")
	}
	field, ok := group.ScalarStructure().(algebra.PrimeField[S])
	if !ok {
		return nil, errs.NewFailed("invalid group scalar structure")
	}
	if (xi % 8) != 0 {
		return nil, errs.NewValidation("invalid xi")
	}
	defaultSuite, err := ot.NewDefaultSuite(xi, l)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create default suite")
	}

	s := &Suite[G, S]{
		*defaultSuite,
		group,
		field,
	}
	return s, nil
}

func (s *Suite[G, S]) Group() algebra.PrimeGroup[G, S] {
	return s.group
}

func (s *Suite[G, S]) Field() algebra.PrimeField[S] {
	return s.scalarField
}

type ReceiverOutput[S algebra.PrimeFieldElement[S]] struct {
	ot.ReceiverOutput[S]
}

func NewReceiverOutput[S algebra.PrimeFieldElement[S]](xi, l int) *ReceiverOutput[S] {
	r := make([][]S, xi)
	for i := range r {
		r[i] = make([]S, l)
	}
	return &ReceiverOutput[S]{
		ot.ReceiverOutput[S]{
			Messages: r,
		},
	}
}

func (r *ReceiverOutput[S]) ToBitsOutput(b int) (*vsot.ReceiverOutput, error) {
	if b < 16 {
		return nil, errs.NewValidation("invalid hash size")
	}
	h, err := blake2b.New(b, nil)
	if err != nil {
		return nil, errs.NewFailed("failed to create hasher")
	}

	out := &vsot.ReceiverOutput{
		ReceiverOutput: ot.ReceiverOutput[[]byte]{
			Choices:  r.Choices,
			Messages: make([][][]byte, len(r.Messages)),
		},
	}
	for xi := range r.Messages {
		out.Messages[xi] = make([][]byte, len(r.Messages[xi]))
		for l, m := range r.Messages[xi] {
			h.Reset()
			h.Write(m.Bytes())
			out.Messages[xi][l] = h.Sum(nil)
		}
	}

	return out, nil
}

type SenderOutput[S algebra.PrimeFieldElement[S]] struct {
	ot.SenderOutput[S]
}

func NewSenderOutput[S algebra.PrimeFieldElement[S]](xi, l int) *SenderOutput[S] {
	s := make([][2][]S, xi)
	for i := range s {
		s[i][0] = make([]S, l)
		s[i][1] = make([]S, l)
	}
	return &SenderOutput[S]{
		ot.SenderOutput[S]{
			Messages: s,
		},
	}
}

func (s *SenderOutput[S]) ToBitsOutput(b int) (*vsot.SenderOutput, error) {
	if b < 16 {
		return nil, errs.NewValidation("invalid hash size")
	}
	h, err := blake2b.New(b, nil)
	if err != nil {
		return nil, errs.NewFailed("failed to create hasher")
	}

	out := &vsot.SenderOutput{
		SenderOutput: ot.SenderOutput[[]byte]{
			Messages: make([][2][][]byte, len(s.Messages)),
		},
	}
	for xi := range s.Messages {
		out.Messages[xi][0] = make([][]byte, len(s.Messages[xi][0]))
		out.Messages[xi][1] = make([][]byte, len(s.Messages[xi][1]))
		for l := range s.Messages[xi][0] {
			h.Reset()
			h.Write(s.Messages[xi][0][l].Bytes())
			out.Messages[xi][0][l] = h.Sum(nil)
			h.Reset()
			h.Write(s.Messages[xi][1][l].Bytes())
			out.Messages[xi][1][l] = h.Sum(nil)
		}
	}

	return out, nil
}
