package pedersen

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/errs-go/errs"
)

func SampleTrapdoorKey[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](group algebra.PrimeGroup[E, S], prng io.Reader) (*TrapdoorKey[E, S], error) {
	if group == nil || prng == nil {
		return nil, ErrIsNil.WithMessage("group and prng must not be nil")
	}
	sf := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
	lambda, err := algebrautils.Random(
		sf, prng,
		func(l S) bool { return !l.IsZero() },
		func(l S) bool { return !l.IsOne() },
	)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to sample lambda")
	}
	out, err := NewTrapdoorKey(group.Generator(), lambda)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Pedersen trapdoor key")
	}
	return out, nil
}

func NewTrapdoorKey[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](g E, lambda S) (*TrapdoorKey[E, S], error) {
	if utils.IsNil(g) || utils.IsNil(lambda) {
		return nil, ErrInvalidArgument.WithMessage("generator and trapdoor value cannot be nil")
	}
	if g.IsOpIdentity() || !g.IsTorsionFree() {
		return nil, ErrInvalidArgument.WithMessage("generator cannot be the identity element or have torsion")
	}
	if lambda.IsZero() {
		return nil, ErrInvalidArgument.WithMessage("trapdoor value cannot be zero")
	}
	if lambda.IsOne() {
		return nil, ErrInvalidArgument.WithMessage("trapdoor value cannot be one")
	}
	t := &TrapdoorKey[E, S]{
		CommitmentKey: CommitmentKey[E, S]{
			g: g,
			h: g.ScalarOp(lambda),
		},
		lambda: lambda,
	}
	return t, nil
}

type TrapdoorKey[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	CommitmentKey[E, S]
	lambda S
}

type trapdoorKeyDTO[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	G      E `cbor:"g"`
	Lambda S `cbor:"lambda"`
}

func (t *TrapdoorKey[E, S]) CommitWithWitness(message *Message[S], witness *Witness[S]) (*Commitment[E, S], error) {
	if message == nil || witness == nil {
		return nil, ErrIsNil.WithMessage("message and witness must not be nil")
	}
	// c = mG + rH = mG + r(lambda*G) = (m + lambda*r)G
	out, err := NewCommitment(t.g.ScalarOp(message.m.Add(t.lambda.Mul(witness.r))))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create commitment")
	}
	return out, nil
}

func (t *TrapdoorKey[E, S]) Equivocate(message *Message[S], witness *Witness[S], newMessage *Message[S]) (*Witness[S], error) {
	if message == nil || witness == nil || newMessage == nil {
		return nil, ErrIsNil.WithMessage("message, witness, and new message must not be nil")
	}
	// To equivocate, we need to find r' such that:
	// mG + rH = m'G + r'H
	//  => (m - m')G = ((r' - r)*lambda)G
	//  => r' = r + lambda^-1 * (m - m')
	lambdaInv, err := t.lambda.TryInv()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("trapdoor value is not invertible")
	}
	out, err := NewWitness(witness.r.Add(lambdaInv.Mul(message.m.Sub(newMessage.m))))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new witness")
	}
	return out, nil
}

func (t *TrapdoorKey[E, S]) Lambda() S {
	return t.lambda
}

func (t *TrapdoorKey[E, S]) Export() *CommitmentKey[E, S] {
	return t.CommitmentKey.Clone()
}

func (t *TrapdoorKey[E, S]) Equal(other *TrapdoorKey[E, S]) bool {
	if t == nil || other == nil {
		return t == other
	}
	return t.g.Equal(other.g) && t.lambda.Equal(other.lambda)
}

func (t *TrapdoorKey[E, S]) HashCode() base.HashCode {
	return t.g.HashCode().Combine(t.lambda.HashCode())
}

func (t *TrapdoorKey[E, S]) MarshalCBOR() ([]byte, error) {
	dto := &trapdoorKeyDTO[E, S]{
		G:      t.g,
		Lambda: t.lambda,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not marshal trapdoor key to CBOR")
	}
	return out, nil
}

func (t *TrapdoorKey[E, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[trapdoorKeyDTO[E, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("could not unmarshal trapdoor key from CBOR")
	}
	tt, err := NewTrapdoorKey(dto.G, dto.Lambda)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid trapdoor key data")
	}
	*t = *tt
	return nil
}
