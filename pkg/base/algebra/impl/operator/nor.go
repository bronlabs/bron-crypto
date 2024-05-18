package operator

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

var _ algebra.JointDenial[any] = (*JointDenial[any])(nil)

type JointDenial[E algebra.Element] struct {
	BiEndoFunction[E]
	BinaryOperator[E]
	RightAssociativeBiEndoFunction[E]
}

func (a *JointDenial[E]) Nor(x, y E) E {
	out, err := a.Map(x, y)
	if err != nil {
		panic(err)
	}
	return out
}

func NewJointDenialOperator[E algebra.Element](name algebra.Operator, f func(x, y E) (E, error)) algebra.JointDenial[E] {
	out := &JointDenial[E]{}
	out.Name_ = name
	out.Map_ = f
	return out
}
