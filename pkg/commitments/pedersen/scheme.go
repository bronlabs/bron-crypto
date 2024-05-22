package pedersencommitments

import (
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
)

var _ commitments.HomomorphicCommitmentScheme[Message, *Commitment, *Opening] = (*homomorphicScheme)(nil)
var scheme = &homomorphicScheme{}

type homomorphicScheme struct{}

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
		witness: x.witness.Clone(),
	}
	for _, y := range ys {
		if err := y.Validate(); err != nil {
			return nil, errs.WrapFailed(err, "invalid opening (2nd operand)")
		}
		acc.message = acc.message.Add(y.message)
		acc.witness = acc.witness.Add(y.witness)
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

	curve := x.witness.ScalarField().Curve()
	scale := curve.ScalarField().Scalar().SetNat(n)
	opening := &Opening{
		message: x.Message().Mul(scale),
		witness: x.witness.Mul(scale),
	}

	return opening, nil
}
