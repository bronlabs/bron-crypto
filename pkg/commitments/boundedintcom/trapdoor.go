package boundedintcom

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/errs-go/errs"
)

func SampleTrapdoorKey(keyLen uint, messageSlack int, prng io.Reader) (*TrapdoorKey, error) {
	group, s, t, lambda, err := SamplePedersenParameters(keyLen, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample pedersen parameters")
	}
	ck, err := newCommitmentKey(s, t, messageSlack)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create commitment key")
	}
	return &TrapdoorKey{
		CommitmentKey: *ck,
		group:         group,
		lambda:        lambda,
	}, nil
}

func NewTrapdoorKey(t *znstar.RSAGroupElementKnownOrder, lambda *num.Uint, messageSlack int) (*TrapdoorKey, error) {
	if t == nil || lambda == nil {
		return nil, ErrIsNil.WithMessage("t and lambda must not be nil")
	}
	if t.IsOpIdentity() || !t.IsTorsionFree() {
		return nil, ErrInvalidArgument.WithMessage("t cannot be the identity element or have torsion")
	}
	if !t.Value().Decrement().Nat().Coprime(t.Modulus().Nat()) {
		return nil, ErrInvalidArgument.WithMessage("t is not a generator of QR(NHat)")
	}
	p, err := num.NPlus().FromNatCT(t.Arithmetic().Params.PNat)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create p from arithmetic parameters")
	}
	q, err := num.NPlus().FromNatCT(t.Arithmetic().Params.QNat)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create q from arithmetic parameters")
	}
	phiNHatOver4 := p.Rsh(1).Mul(q.Rsh(1))
	if !lambda.Modulus().Equal(phiNHatOver4) {
		return nil, ErrInvalidArgument.WithMessage("lambda modulus must equal φ(NHat)/4")
	}
	if lambda.IsOne() || !lambda.IsUnit() {
		return nil, ErrInvalidArgument.WithMessage("lambda must be a unit mod φ(NHat)/4 and not equal to one")
	}
	s := t.ExpI(lambda.Lift())
	ck, err := newCommitmentKey(s.ForgetOrder(), t.ForgetOrder(), messageSlack)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create commitment key")
	}
	return &TrapdoorKey{
		CommitmentKey: *ck,
		group:         t.Group(),
		lambda:        lambda,
	}, nil
}

type TrapdoorKey struct {
	CommitmentKey
	group  *znstar.RSAGroupKnownOrder
	lambda *num.Uint
}

type trapdoorKeyDTO struct {
	T            *znstar.RSAGroupElementKnownOrder `cbor:"t"`
	Lambda       *num.Uint                         `cbor:"lambda"`
	MessageSlack int                               `cbor:"slack"`
}

func (k *TrapdoorKey) CommitWithWitness(message *Message, witness *Witness) (*Commitment, error) {
	if message == nil || witness == nil {
		return nil, ErrIsNil.WithMessage("message and witness cannot be nil")
	}
	if !k.WitnessInRange(witness) {
		return nil, ErrInvalidArgument.WithMessage("witness value out of range")
	}
	if !k.MessageInRange(message) {
		return nil, ErrInvalidArgument.WithMessage("message value out of range")
	}
	t, err := k.t.LearnOrder(k.group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn order")
	}
	// s^m * t^r = t^(lambda*m + r)
	out, err := NewCommitment(t.ExpI(message.m.Mul(k.lambda.Lift()).Add(witness.r)).ForgetOrder())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create commitment from message and witness")
	}
	return out, nil
}

func (t *TrapdoorKey) Group() *znstar.RSAGroupKnownOrder {
	return t.group
}

func (t *TrapdoorKey) Lambda() *num.Uint {
	return t.lambda
}

func (k *TrapdoorKey) Export() *CommitmentKey {
	return k.CommitmentKey.Clone()
}

func (k *TrapdoorKey) Equal(other *TrapdoorKey) bool {
	if k == nil || other == nil {
		return k == other
	}
	return k.t.Equal(other.t) && k.lambda.Equal(other.lambda) && k.messageSlack == other.messageSlack
}

func (k *TrapdoorKey) HashCode() base.HashCode {
	return k.t.HashCode().Combine(k.lambda.HashCode())
}

func (k *TrapdoorKey) MarshalCBOR() ([]byte, error) {
	learned, err := k.t.LearnOrder(k.group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn order")
	}
	dto := &trapdoorKeyDTO{
		T:            learned,
		Lambda:       k.lambda,
		MessageSlack: k.messageSlack,
	}
	out, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal trapdoor key")
	}
	return out, nil
}

func (k *TrapdoorKey) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[trapdoorKeyDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal trapdoor key")
	}
	kk, err := NewTrapdoorKey(dto.T, dto.Lambda, dto.MessageSlack)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid trapdoor key data")
	}
	*k = *kk
	return nil
}
