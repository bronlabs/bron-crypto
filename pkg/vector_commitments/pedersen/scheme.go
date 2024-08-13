package pedersenvectorcommitments

//import (
//	"github.com/cronokirby/saferith"
//
//	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
//	"github.com/copperexchange/krypton-primitives/pkg/commitments"
//)
//
//var _ commitments.HomomorphicCommitmentScheme[Vector, *VectorCommitment, *Opening] = (*vectorHomomorphicScheme)(nil)
//
//type vectorHomomorphicScheme struct{}
//
//var scheme = &vectorHomomorphicScheme{}
//
//func (*vectorHomomorphicScheme) CombineCommitments(x *VectorCommitment, ys ...*VectorCommitment) (*VectorCommitment, error) {
//	if err := x.Validate(); err != nil {
//		return nil, errs.WrapValidation(err, "unvalid commitment (1st operand)")
//	}
//	acc := &VectorCommitment{
//		value: x.value.Clone(),
//	}
//	for _, y := range ys {
//		if err := y.Validate(); err != nil {
//			return nil, errs.WrapValidation(err, "unvalid commitment (2nd operand)")
//		}
//		acc.value = acc.value.Add(y.value)
//	}
//	return acc, nil
//}
//
//func (*vectorHomomorphicScheme) ScaleCommitment(x *VectorCommitment, n *saferith.Nat) (*VectorCommitment, error) {
//	if err := x.Validate(); err != nil {
//		return nil, errs.WrapValidation(err, "unvalid commitment")
//	}
//	if n == nil {
//		return nil, errs.NewIsNil("scalar is nil")
//	}
//	curve := x.value.Curve()
//	scale := curve.ScalarField().Scalar().SetNat(n)
//	return &VectorCommitment{
//			value: x.value.ScalarMul(scale),
//		},
//		nil
//}
//
//func (*vectorHomomorphicScheme) CombineOpenings(x *Opening, ys ...*Opening) (*Opening, error) {
//	if err := x.Validate(); err != nil {
//		return nil, errs.WrapValidation(err, "unvalid opening (1st operand)")
//	}
//	acc := &Opening{vector: make(Vector, len(x.vector)), witness: x.witness.Clone()}
//	copy(acc.vector, x.vector)
//	for _, y := range ys {
//		if len(y.vector) != len(x.vector) {
//			return nil, errs.NewFailed("vector length mismatch")
//		}
//		if err := y.Validate(); err != nil {
//			return nil, errs.WrapValidation(err, "unvalid opening (2nd operand)")
//		}
//		acc.witness = acc.witness.Add(y.witness)
//		for j, yElement := range y.vector {
//			acc.vector[j] = acc.vector[j].Add(yElement)
//		}
//	}
//	return acc, nil
//}
//
//func (*vectorHomomorphicScheme) ScaleOpening(x *Opening, n *saferith.Nat) (*Opening, error) {
//	if err := x.Validate(); err != nil {
//		return nil, errs.WrapValidation(err, "unvalid opening")
//	}
//	if n == nil {
//		return nil, errs.NewIsNil("scalar is nil")
//	}
//	curve := x.witness.ScalarField().Curve()
//	scale := curve.ScalarField().Scalar().SetNat(n)
//	acc := &Opening{vector: make(Vector, len(x.vector)), witness: x.witness.Clone()}
//	copy(acc.vector, x.vector)
//	acc.witness = acc.witness.Mul(scale)
//	for i := range x.vector {
//		acc.vector[i] = acc.vector[i].Mul(scale)
//	}
//	return acc, nil
//}
