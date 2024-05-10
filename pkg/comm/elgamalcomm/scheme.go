package elgamalcomm

import (
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/comm"
)

var _ comm.HomomorphicCommitmentScheme[Message, *Commitment, *Opening] = (*homomorphicScheme)(nil)

type homomorphicScheme struct{}

var scheme = &homomorphicScheme{}

func (*homomorphicScheme) CombineCommitments(x *Commitment, ys ...*Commitment) (*Commitment, error) {
	if err := x.Validate(); err != nil {
		return nil, errs.NewArgument("invalid commitment (1st operand)")
	}

	acc := &Commitment{
		c1: x.c1.Clone(),
		c2: x.c2.Clone(),
	}
	for _, y := range ys {
		if err := y.Validate(); err != nil {
			return nil, errs.NewArgument("invalid commitment (2nd operand)")
		}
		acc.c1 = acc.c1.Add(y.c1)
		acc.c2 = acc.c2.Add(y.c2)
	}

	return acc, nil
}

func (*homomorphicScheme) ScaleCommitment(x *Commitment, n *saferith.Nat) (*Commitment, error) {
	if err := x.Validate(); err != nil {
		return nil, errs.NewArgument("invalid commitment")
	}

	curve := x.c1.Curve()
	scale := curve.ScalarField().Scalar().SetNat(n)
	c := &Commitment{
		c1: x.c1.ScalarMul(scale),
		c2: x.c2.ScalarMul(scale),
	}

	return c, nil
}

func (*homomorphicScheme) CombineOpenings(x *Opening, ys ...*Opening) (*Opening, error) {
	if err := x.Validate(); err != nil {
		return nil, errs.NewArgument("invalid opening (1st operand)")
	}

	acc := &Opening{
		message: x.message.Clone(),
		witness: x.witness.Clone(),
	}
	for _, y := range ys {
		if err := y.Validate(); err != nil {
			return nil, errs.NewArgument("invalid opening (2nd operand)")
		}
		acc.message = acc.message.Add(y.message)
		acc.witness = acc.witness.Add(y.witness)
	}

	return acc, nil
}

func (*homomorphicScheme) ScaleOpening(x *Opening, n *saferith.Nat) (*Opening, error) {
	if err := x.Validate(); err != nil {
		return nil, errs.NewArgument("invalid opening")
	}

	curve := x.witness.ScalarField().Curve()
	scale := curve.ScalarField().Scalar().SetNat(n)
	opening := &Opening{
		message: x.Message().ScalarMul(scale),
		witness: x.witness.Mul(scale),
	}

	return opening, nil
}
