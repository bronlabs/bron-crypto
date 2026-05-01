package pedersen

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/commitments/internal"
	ts "github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/errs-go/errs"
)

func SampleCommitmentKey[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](group algebra.PrimeGroup[E, S], prng io.Reader) (*CommitmentKey[E, S], error) {
	if group == nil || prng == nil {
		return nil, ErrIsNil.WithMessage("group and prng must not be nil")
	}
	h, err := algebrautils.Random(group, prng, func(e E) bool { return !e.IsOpIdentity() && !e.Equal(group.Generator()) })
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to generate random non-identity element")
	}
	return NewCommitmentKeyUnchecked(group.Generator(), h)
}

func ExtractCommitmentKey[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](transcript ts.Transcript, label string, basePoint E) (*CommitmentKey[E, S], error) {
	if utils.IsNil(basePoint) {
		return nil, ErrInvalidArgument.WithMessage("basePoint cannot be nil")
	}
	if transcript == nil {
		return nil, ErrInvalidArgument.WithMessage("transcript cannot be nil")
	}
	if label == "" {
		return nil, ErrInvalidArgument.WithMessage("label cannot be empty")
	}

	group := algebra.StructureMustBeAs[algebra.PrimeGroup[E, S]](basePoint.Structure())
	h, err := ts.Extract(transcript, label, group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to extract second generator for pedersen key")
	}
	out, err := NewCommitmentKeyUnchecked(basePoint, h)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Pedersen commitment key")
	}
	return out, nil
}

func NewCommitmentKeyUnchecked[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](g, h E) (*CommitmentKey[E, S], error) {
	if utils.IsNil(g) || utils.IsNil(h) {
		return nil, ErrIsNil.WithMessage("generators must not be nil")
	}
	if g.Equal(h) {
		return nil, ErrInvalidArgument.WithMessage("generators must be distinct")
	}
	if g.IsOpIdentity() || h.IsOpIdentity() {
		return nil, ErrIsIdentity.WithMessage("generators must not be the identity element")
	}
	return &CommitmentKey[E, S]{g: g, h: h}, nil
}

type CommitmentKey[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	g E
	h E
}

type commitmentKeyDTO[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	G E `cbor:"g"`
	H E `cbor:"h"`
}

func (k *CommitmentKey[E, S]) SampleWitness(prng io.Reader) (*Witness[S], error) {
	if prng == nil {
		return nil, ErrIsNil.WithMessage("prng must not be nil")
	}
	r, err := k.WitnessGroup().Random(prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to generate random witness")
	}
	return &Witness[S]{r: r}, nil
}

func (k *CommitmentKey[E, S]) CommitWithWitness(message *Message[S], witness *Witness[S]) (*Commitment[E, S], error) {
	if message == nil || witness == nil {
		return nil, ErrIsNil.WithMessage("message and witness must not be nil")
	}
	out, err := NewCommitment(k.g.ScalarOp(message.Value()).Op(k.h.ScalarOp(witness.r)))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create commitment")
	}
	return out, nil
}

func (k *CommitmentKey[E, S]) Open(commitment *Commitment[E, S], message *Message[S], witness *Witness[S]) error {
	if err := internal.GenericOpen(k, commitment, message, witness); err != nil {
		return errs.Wrap(err).WithMessage("could not open commitment")
	}
	return nil
}

func (k *CommitmentKey[E, S]) WitnessOp(first, second *Witness[S], rest ...*Witness[S]) (*Witness[S], error) {
	if first == nil || second == nil {
		return nil, ErrIsNil.WithMessage("first and second witnesses must not be nil")
	}
	if len(rest) > 0 && sliceutils.Any(rest, utils.IsNil[*Witness[S]]) {
		return nil, ErrIsNil.WithMessage("all witnesses must not be nil")
	}
	restValues, err := sliceutils.MapOrError(rest, func(w *Witness[S]) (S, error) {
		if w == nil {
			return *new(S), ErrIsNil.WithMessage("witness must not be nil")
		}
		return w.r, nil
	})
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid witness in rest witnesses")
	}
	out, err := NewWitness(algebrautils.Fold(first.r.Op(second.r), restValues...))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new witness")
	}
	return out, nil
}

func (k *CommitmentKey[E, S]) WitnessOpInv(w *Witness[S]) (*Witness[S], error) {
	if w == nil {
		return nil, ErrIsNil.WithMessage("witness must not be nil")
	}
	out, err := NewWitness(w.r.OpInv())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new witness")
	}
	return out, nil
}

func (k *CommitmentKey[E, S]) WitnessScalarOp(w *Witness[S], scalar S) (*Witness[S], error) {
	if w == nil {
		return nil, ErrIsNil.WithMessage("witness must not be nil")
	}
	if utils.IsNil(scalar) {
		return nil, ErrIsNil.WithMessage("scalar must not be nil")
	}
	out, err := NewWitness(w.r.Mul(scalar))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new witness")
	}
	return out, nil
}

func (k *CommitmentKey[E, S]) MessageOp(first, second *Message[S], rest ...*Message[S]) (*Message[S], error) {
	if first == nil || second == nil {
		return nil, ErrIsNil.WithMessage("first and second messages must not be nil")
	}
	if len(rest) > 0 && sliceutils.Any(rest, utils.IsNil[*Message[S]]) {
		return nil, ErrIsNil.WithMessage("all messages must not be nil")
	}
	restValues, err := sliceutils.MapOrError(rest, func(m *Message[S]) (S, error) {
		if m == nil {
			return *new(S), ErrIsNil.WithMessage("message must not be nil")
		}
		return m.m, nil
	})
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid message in rest messages")
	}
	out, err := NewMessage(algebrautils.Fold(first.m.Op(second.m), restValues...))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new message")
	}
	return out, nil
}

func (k *CommitmentKey[E, S]) MessageOpInv(m *Message[S]) (*Message[S], error) {
	if m == nil {
		return nil, ErrIsNil.WithMessage("message must not be nil")
	}
	out, err := NewMessage(m.m.OpInv())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new message")
	}
	return out, nil
}

func (k *CommitmentKey[E, S]) MessageScalarOp(m *Message[S], scalar S) (*Message[S], error) {
	if m == nil {
		return nil, ErrIsNil.WithMessage("message must not be nil")
	}
	if utils.IsNil(scalar) {
		return nil, ErrIsNil.WithMessage("scalar must not be nil")
	}
	out, err := NewMessage(m.m.Mul(scalar))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new message")
	}
	return out, nil
}

func (k *CommitmentKey[E, S]) CommitmentOp(first, second *Commitment[E, S], rest ...*Commitment[E, S]) (*Commitment[E, S], error) {
	if first == nil || second == nil {
		return nil, ErrIsNil.WithMessage("first and second commitments must not be nil")
	}
	if len(rest) > 0 && sliceutils.Any(rest, utils.IsNil[*Commitment[E, S]]) {
		return nil, ErrIsNil.WithMessage("all commitments must not be nil")
	}
	restValues, err := sliceutils.MapOrError(rest, func(c *Commitment[E, S]) (E, error) {
		if c == nil {
			return *new(E), ErrIsNil.WithMessage("commitment must not be nil")
		}
		return c.v, nil
	})
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid commitment in rest commitments")
	}
	out, err := NewCommitment(algebrautils.Fold(first.v.Op(second.v), restValues...))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new commitment")
	}
	return out, nil
}

func (k *CommitmentKey[E, S]) CommitmentOpInv(c *Commitment[E, S]) (*Commitment[E, S], error) {
	if c == nil {
		return nil, ErrIsNil.WithMessage("commitment must not be nil")
	}
	out, err := NewCommitment(c.v.OpInv())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new commitment")
	}
	return out, nil
}

func (k *CommitmentKey[E, S]) CommitmentScalarOp(c *Commitment[E, S], scalar S) (*Commitment[E, S], error) {
	if c == nil {
		return nil, ErrIsNil.WithMessage("commitment must not be nil")
	}
	if utils.IsNil(scalar) {
		return nil, ErrIsNil.WithMessage("scalar must not be nil")
	}
	out, err := NewCommitment(c.v.ScalarOp(scalar))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new commitment")
	}
	return out, nil
}

func (k *CommitmentKey[E, S]) ReRandomise(c *Commitment[E, S], witnessShift *Witness[S]) (*Commitment[E, S], error) {
	if c == nil || witnessShift == nil {
		return nil, ErrIsNil.WithMessage("commitment and witness shift must not be nil")
	}
	out, err := NewCommitment(c.v.Op(k.h.ScalarOp(witnessShift.r)))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new commitment")
	}
	return out, nil
}

func (k *CommitmentKey[E, S]) Shift(c *Commitment[E, S], message *Message[S]) (*Commitment[E, S], error) {
	if c == nil || message == nil {
		return nil, ErrIsNil.WithMessage("commitment and message must not be nil")
	}
	out, err := NewCommitment(c.v.Op(k.g.ScalarOp(message.Value())))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new commitment")
	}
	return out, nil
}

func (k *CommitmentKey[E, S]) G() E {
	return k.g
}

func (k *CommitmentKey[E, S]) H() E {
	return k.h
}

func (k *CommitmentKey[E, S]) MessageGroup() algebra.PrimeField[S] {
	return algebra.StructureMustBeAs[algebra.PrimeField[S]](k.CommitmentGroup().ScalarStructure())
}

func (k *CommitmentKey[E, S]) WitnessGroup() algebra.PrimeField[S] {
	return algebra.StructureMustBeAs[algebra.PrimeField[S]](k.CommitmentGroup().ScalarStructure())
}

func (k *CommitmentKey[E, S]) CommitmentGroup() algebra.PrimeGroup[E, S] {
	return algebra.StructureMustBeAs[algebra.PrimeGroup[E, S]](k.g.Structure())
}

func (k *CommitmentKey[E, S]) Equal(other *CommitmentKey[E, S]) bool {
	if k == nil || other == nil {
		return k == other
	}
	return k.g.Equal(other.g) && k.h.Equal(other.h)
}

func (k *CommitmentKey[E, S]) HashCode() base.HashCode {
	return k.g.HashCode().Combine(k.h.HashCode())
}

func (k *CommitmentKey[E, S]) Clone() *CommitmentKey[E, S] {
	return &CommitmentKey[E, S]{
		g: k.g.Clone(),
		h: k.h.Clone(),
	}
}

func (k *CommitmentKey[E, S]) MarshalCBOR() ([]byte, error) {
	dto := &commitmentKeyDTO[E, S]{
		G: k.g,
		H: k.h,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal commitment key to CBOR")
	}
	return out, nil
}

func (k *CommitmentKey[E, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[commitmentKeyDTO[E, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal commitment key from CBOR")
	}
	kk, err := NewCommitmentKeyUnchecked(dto.G, dto.H)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid commitment key")
	}
	*k = *kk
	return nil
}
