package ecbbot

import (
	"encoding/binary"

	"golang.org/x/crypto/blake2b"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
)

// Suite configures EC batching base OTs over a prime-order group.
type Suite[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	ot.DefaultSuite

	group       algebra.PrimeGroup[G, S]
	scalarField algebra.PrimeField[S]
}

// NewSuite creates an EC BBOT suite for batch size xi and block length l.
func NewSuite[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](xi, l int, group algebra.PrimeGroup[G, S]) (*Suite[G, S], error) {
	if group == nil {
		return nil, ot.ErrInvalidArgument.WithMessage("invalid group")
	}
	field, ok := group.ScalarStructure().(algebra.PrimeField[S])
	if !ok {
		return nil, ot.ErrFailed.WithMessage("invalid group scalar structure")
	}
	if (xi % 8) != 0 {
		return nil, ot.ErrInvalidArgument.WithMessage("invalid xi")
	}
	defaultSuite, err := ot.NewDefaultSuite(xi, l)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create default suite")
	}

	s := &Suite[G, S]{
		*defaultSuite,
		group,
		field,
	}
	return s, nil
}

// Group returns the underlying prime-order group.
func (s *Suite[G, S]) Group() algebra.PrimeGroup[G, S] {
	return s.group
}

// Field returns the scalar field used with the group.
func (s *Suite[G, S]) Field() algebra.PrimeField[S] {
	return s.scalarField
}

// ReceiverOutput holds scalar outputs for the receiver side.
type ReceiverOutput[S algebra.PrimeFieldElement[S]] struct {
	ot.ReceiverOutput[S]
}

// NewReceiverOutput allocates an empty receiver output structure for xi and l.
func NewReceiverOutput[S algebra.PrimeFieldElement[S]](xi, l int) *ReceiverOutput[S] {
	r := make([][]S, xi)
	for i := range r {
		r[i] = make([]S, l)
	}
	return &ReceiverOutput[S]{
		ot.ReceiverOutput[S]{
			Choices:  nil,
			Messages: r,
		},
	}
}

// ToBitsOutput hashes scalar outputs into byte strings usable by VSOT/extension.
func (r *ReceiverOutput[S]) ToBitsOutput(byteLen int, key []byte) (*vsot.ReceiverOutput, error) {
	if byteLen < 16 || len(key) < 16 {
		return nil, ot.ErrInvalidArgument.WithMessage("invalid hash or key size")
	}
	h, err := blake2b.New(byteLen, key)
	if err != nil {
		return nil, ot.ErrFailed.WithMessage("failed to create hasher")
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
			h.Write(binary.LittleEndian.AppendUint64(nil, uint64(xi)))
			h.Write(binary.LittleEndian.AppendUint64(nil, uint64(l)))
			h.Write(m.Bytes())
			out.Messages[xi][l] = h.Sum(nil)
		}
	}

	return out, nil
}

// SenderOutput holds scalar branch outputs for the sender side.
type SenderOutput[S algebra.PrimeFieldElement[S]] struct {
	ot.SenderOutput[S]
}

// NewSenderOutput allocates an empty sender output structure for xi and l.
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

// ToBitsOutput hashes scalar outputs into byte strings usable by VSOT/extension.
func (s *SenderOutput[S]) ToBitsOutput(byteLen int, key []byte) (*vsot.SenderOutput, error) {
	if byteLen < 16 || len(key) < 16 {
		return nil, ot.ErrInvalidArgument.WithMessage("invalid hash or key size")
	}
	h, err := blake2b.New(byteLen, key)
	if err != nil {
		return nil, ot.ErrFailed.WithMessage("failed to create hasher")
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
			h.Write(binary.LittleEndian.AppendUint64(nil, uint64(xi)))
			h.Write(binary.LittleEndian.AppendUint64(nil, uint64(l)))
			h.Write(s.Messages[xi][0][l].Bytes())
			out.Messages[xi][0][l] = h.Sum(nil)
			h.Reset()
			h.Write(binary.LittleEndian.AppendUint64(nil, uint64(xi)))
			h.Write(binary.LittleEndian.AppendUint64(nil, uint64(l)))
			h.Write(s.Messages[xi][1][l].Bytes())
			out.Messages[xi][1][l] = h.Sum(nil)
		}
	}

	return out, nil
}
