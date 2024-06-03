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
		Value: x.Value.Clone(),
	}
	for _, y := range ys {
		if err := y.Validate(); err != nil {
			return nil, errs.WrapFailed(err, "invalid commitment (2nd operand)")
		}
		acc.Value = acc.Value.Add(y.Value)
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

	curve := x.Value.Curve()
	scalar := curve.ScalarField().Scalar().SetNat(n)
	c := &Commitment{
		Value: x.Value.ScalarMul(scalar),
	}

	return c, nil
}

func (*homomorphicScheme) CombineOpenings(x *Opening, ys ...*Opening) (*Opening, error) {
	if err := x.Validate(); err != nil {
		return nil, errs.WrapFailed(err, "invalid opening (1st operand)")
	}

	acc := &Opening{
		Message: x.Message.Clone(),
		Witness: x.Witness.Clone(),
	}
	for _, y := range ys {
		if err := y.Validate(); err != nil {
			return nil, errs.WrapFailed(err, "invalid opening (2nd operand)")
		}
		acc.Message = acc.Message.Add(y.Message)
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
		Message: x.Message.Mul(scale),
		Witness: x.Witness.Mul(scale),
	}

	return opening, nil
}
