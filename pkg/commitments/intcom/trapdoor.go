package intcom

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/internal"
	"github.com/bronlabs/errs-go/errs"
)

func SampleTrapdoorKey(keyLen uint, prng io.Reader) (*TrapdoorKey, error) {
	group, s, t, lambda, err := SamplePedersenParameters(keyLen, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not sample pedersen parameters")
	}
	ck, err := newCommitmentKey(s, t)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create commitment key")
	}
	return &TrapdoorKey{
		CommitmentKey: *ck,
		group:         group,
		lambda:        lambda,
	}, nil
}

func NewTrapdoorKey(t *znstar.RSAGroupElementKnownOrder, lambda *num.Uint) (*TrapdoorKey, error) {
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
	ck, err := newCommitmentKey(s.ForgetOrder(), t.ForgetOrder())
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
	T      *znstar.RSAGroupElementKnownOrder `cbor:"t"`
	Lambda *num.Uint                         `cbor:"lambda"`
}

func (k *TrapdoorKey) CommitWithWitness(message *Message, witness *Witness) (*Commitment, error) {
	if message == nil || witness == nil {
		return nil, ErrIsNil.WithMessage("message and witness cannot be nil")
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

func (k *TrapdoorKey) CommitmentOp(first, second *Commitment, rest ...*Commitment) (*Commitment, error) {
	if first == nil || second == nil {
		return nil, ErrIsNil.WithMessage("first and second commitments cannot be nil")
	}
	firstValue, err := first.Value().LearnOrder(k.group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn order of first commitment value")
	}
	secondValue, err := second.Value().LearnOrder(k.group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn order of second commitment value")
	}
	restValues, err := sliceutils.MapOrError(rest, func(w *Commitment) (*znstar.RSAGroupElementKnownOrder, error) {
		if utils.IsNil(w) {
			return nil, commitments.ErrIsNil.WithMessage("object must not be nil")
		}
		out, err := w.Value().LearnOrder(k.group)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not learn order of commitment value")
		}
		return out, nil
	})
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid commitment in rest commitments")
	}
	outValue, err := internal.OpValues(firstValue, secondValue, restValues...)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to combine commitment values")
	}
	out, err := NewCommitment(outValue.ForgetOrder())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new commitment from combined value")
	}
	return out, nil
}

func (k *TrapdoorKey) CommitmentOpInv(c *Commitment) (*Commitment, error) {
	if c == nil {
		return nil, ErrIsNil.WithMessage("commitment cannot be nil")
	}
	value, err := c.Value().LearnOrder(k.group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn order of commitment value")
	}
	out, err := NewCommitment(value.OpInv().ForgetOrder())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new commitment from inverse value")
	}
	return out, nil
}

func (k *TrapdoorKey) CommitmentScalarOp(c *Commitment, scalar *num.Int) (*Commitment, error) {
	if c == nil || scalar == nil {
		return nil, ErrIsNil.WithMessage("commitment and scalar cannot be nil")
	}
	value, err := c.Value().LearnOrder(k.group)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not learn order of commitment value")
	}
	out, err := NewCommitment(value.ExpI(scalar).ForgetOrder())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new commitment from scalar multiplied value")
	}
	return out, nil
}

func (k *TrapdoorKey) Equivocate(message *Message, witness *Witness, newMessage *Message, prng io.Reader) (*Witness, error) {
	if message == nil || witness == nil || newMessage == nil || prng == nil {
		return nil, ErrIsNil.WithMessage("message, witness, new message, and prng cannot be nil")
	}
	// s^m * t^r mod n = s^m' * t^r' mod n => t^(lambda*m + r) = t^(lambda*m' + r') => lambda*m + r = lambda*m' + r'
	// => r' = r + lambda*(m - m')
	// Note that the distribution of r' is different than r if m != m'.
	if message.Equal(newMessage) {
		return witness.Clone(), nil
	}
	rPrime := witness.r.Add(k.lambda.Lift().Mul(message.m.Sub(newMessage.m)))
	// r0 is now [0, Phi(NHat)/4)
	r0 := rPrime.Mod(k.lambda.Modulus())
	// We need to find a random number x so that r'' is in [k.witnessLower, k.witnessUpper)
	lowerInner, err := num.Q().New(k.witnessLower.Sub(r0.Lift()), (k.lambda.Modulus()))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create lowerInner from witnessLower and r0")
	}
	xMin, err := lowerInner.Ceil()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compute xMin")
	}

	upperInner, err := num.Q().New(k.witnessUpper.Sub(r0.Lift()).Decrement(), (k.lambda.Modulus()))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create upperInner from witnessUpper and r0")
	}
	xMax, err := upperInner.Floor()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compute xMax")
	}
	x, err := num.Z().Random(xMin, xMax, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to generate random x")
	}
	rDoublePrime := r0.Lift().Add(x.Mul(k.lambda.Modulus().Lift()))
	out, err := NewWitness(rDoublePrime)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create new witness from rDoublePrime")
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
	return k.t.Equal(other.t) && k.lambda.Equal(other.lambda)
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
		T:      learned,
		Lambda: k.lambda,
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
	kk, err := NewTrapdoorKey(dto.T, dto.Lambda)
	if err != nil {
		return errs.Wrap(err).WithMessage("invalid trapdoor key data")
	}
	*k = *kk
	return nil
}
