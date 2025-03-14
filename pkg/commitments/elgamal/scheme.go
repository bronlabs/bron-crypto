package elgamalcommitments

import (
	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
)

var _ commitments.HomomorphicCommitmentScheme[Message, *Commitment, *Opening] = (*homomorphicScheme)(nil)

type homomorphicScheme struct{}

var scheme = &homomorphicScheme{}

func (*homomorphicScheme) CombineCommitments(x *Commitment, ys ...*Commitment) (*Commitment, error) {
	if err := x.Validate(); err != nil {
		return nil, errs.NewArgument("invalid commitment (1st operand)")
	}

	acc := &Commitment{
		C1: x.C1.Clone(),
		C2: x.C2.Clone(),
	}
	for _, y := range ys {
		if err := y.Validate(); err != nil {
			return nil, errs.NewArgument("invalid commitment (2nd operand)")
		}
		acc.C1 = acc.C1.Add(y.C1)
		acc.C2 = acc.C2.Add(y.C2)
	}

	return acc, nil
}

func (*homomorphicScheme) ScaleCommitment(x *Commitment, n *saferith.Nat) (*Commitment, error) {
	if err := x.Validate(); err != nil {
		return nil, errs.NewArgument("invalid commitment")
	}

	curve := x.C1.Curve()
	scale := curve.ScalarField().Scalar().SetNat(n)
	c := &Commitment{
		C1: x.C1.ScalarMul(scale),
		C2: x.C2.ScalarMul(scale),
	}

	return c, nil
}

func (*homomorphicScheme) CombineOpenings(x *Opening, ys ...*Opening) (*Opening, error) {
	if err := x.Validate(); err != nil {
		return nil, errs.NewArgument("invalid opening (1st operand)")
	}

	acc := &Opening{
		Message: x.Message.Clone(),
		Witness: x.Witness.Clone(),
	}
	for _, y := range ys {
		if err := y.Validate(); err != nil {
			return nil, errs.NewArgument("invalid opening (2nd operand)")
		}
		acc.Message = acc.Message.Add(y.Message)
		acc.Witness = acc.Witness.Add(y.Witness)
	}

	return acc, nil
}

func (*homomorphicScheme) ScaleOpening(x *Opening, n *saferith.Nat) (*Opening, error) {
	if err := x.Validate(); err != nil {
		return nil, errs.NewArgument("invalid opening")
	}

	curve := x.Witness.ScalarField().Curve()
	scale := curve.ScalarField().Scalar().SetNat(n)
	opening := &Opening{
		Message: x.Message.ScalarMul(scale),
		Witness: x.Witness.Mul(scale),
	}

	return opening, nil
}
