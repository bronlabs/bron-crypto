package pedersencomm

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/comm"
	"github.com/cronokirby/saferith"
)

var _ comm.HomomorphicCommitmentScheme[Message, *Commitment, *Opening] = (*homomorphicScheme)(nil)

type homomorphicScheme struct{}

var scheme = &homomorphicScheme{}

func (*homomorphicScheme) CombineCommitments(x *Commitment, ys ...*Commitment) (*Commitment, error) {
	if err := x.Validate(); err != nil {
		return nil, errs.WrapFailed(err, "invalid commitment (1st operand)")
	}

	acc := &Commitment{
		value: x.value.Clone(),
	}
	for _, y := range ys {
		if err := y.Validate(); err != nil {
			return nil, errs.WrapFailed(err, "invalid commitment (2nd operand)")
		}
		acc.value = acc.value.Add(y.value)
	}

	return acc, nil
}

func (*homomorphicScheme) ScaleCommitment(x *Commitment, n *saferith.Nat) (*Commitment, error) {
	if err := x.Validate(); err != nil {
		return nil, errs.WrapFailed(err, "invalid commitment")
	}
	if n == nil {
		return nil, errs.NewIsNil("scalar")
	}

	curve := x.value.Curve()
	scalar := curve.ScalarField().Scalar().SetNat(n)
	c := &Commitment{
		value: x.value.ScalarMul(scalar),
	}

	return c, nil
}

func (*homomorphicScheme) CombineOpenings(x *Opening, ys ...*Opening) (*Opening, error) {
	if err := x.Validate(); err != nil {
		return nil, errs.WrapFailed(err, "invalid opening (1st operand)")
	}

	acc := &Opening{
		message: x.message.Clone(),
		Witness: x.Witness.Clone(),
	}
	for _, y := range ys {
		if err := y.Validate(); err != nil {
			return nil, errs.WrapFailed(err, "invalid opening (2nd operand)")
		}
		acc.message = acc.message.Add(y.message)
		acc.Witness = acc.Witness.Add(y.Witness)
	}

	return acc, nil
}

func (*homomorphicScheme) ScaleOpening(x *Opening, n *saferith.Nat) (*Opening, error) {
	if err := x.Validate(); err != nil {
		return nil, errs.WrapFailed(err, "invalid opening")
	}
	if n == nil {
		return nil, errs.NewIsNil("scalar")
	}

	curve := x.Witness.ScalarField().Curve()
	scale := curve.ScalarField().Scalar().SetNat(n)
	opening := &Opening{
		message: x.Message().Mul(scale),
		Witness: x.Witness.Mul(scale),
	}

	return opening, nil
}
