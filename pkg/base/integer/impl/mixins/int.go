package mixins

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/domain"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/cronokirby/saferith"
)

type Z_[S integer.Z[S, E], E integer.Int[S, E]] struct {
	NaturalRig[S, E]
	domain.EuclideanDomain[S, E]

	H HolesZ[S, E]
}

func (z *Z_[S, E]) Name() string {
	return string(integer.ForZ)
}

func (z *Z_[S, E]) Cardinality() *saferith.Modulus {
	// TODO: represent inf
	return nil
}

func (z *Z_[S, E]) Contains(x E) bool {
	return true
}

func (z *Z_[S, E]) Characteristic() *saferith.Nat {
	return new(saferith.Nat).SetUint64(0)
}

func (z *Z_[S, E]) CoPrime(x E, ys ...E) bool {
	out, err := z.Arithmetic().IsCoPrime(x, ys...)
	if err != nil {
		panic(errs.WrapFailed(err, "could not test for coprimality"))
	}
	return out
}

func (z *Z_[S, E]) GCD(x E, ys ...E) (E, error) {
	out, err := z.Arithmetic().GCD(x, ys...)
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not compute GCD")
	}
	return out, nil
}

func (z *Z_[S, E]) LCM(x E, ys ...E) (E, error) {
	out, err := z.Arithmetic().LCM(x, ys...)
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not compute LCM")
	}
	return out, nil
}

func (z *Z_[S, E]) Iter() <-chan E {
	ch := make(chan E, 1)
	current := z.Zero()
	ch <- current
	go func() {
		defer close(ch)
		for {
			current = current.Increment()
			ch <- current
			ch <- current.Neg()
		}
	}()
	return ch
}

type Int_[S integer.Z[S, E], E integer.Int[S, E]] struct {
	NaturalRigElement[S, E]
	domain.EuclideanDomainElement[S, E]

	H HolesInt[S, E]
}

func (n *Int_[S, E]) EuclideanDiv(x E) (E, E) {
	quot, rem, err := n.H.Arithmetic().Div(n.H.Unwrap(), x)
	if err != nil {
		panic(errs.WrapFailed(err, "couldn't take euclidean div"))
	}
	return quot, rem
}

func (n *Int_[S, E]) Factorise() []E {
	panic("something")
}

func (n *Int_[S, E]) AdditiveInverse() E {
	out, err := n.H.Arithmetic().Neg(n.H.Unwrap())
	if err != nil {
		panic(errs.WrapFailed(err, "could not negate"))
	}
	return out
}

func (n *Int_[S, E]) CoPrime(x E) bool {
	return n.H.Structure().CoPrime(n.H.Unwrap(), x)
}

func (n *Int_[S, E]) Inverse(with algebra.Operator) (E, error) {
	switch with {
	case integer.Addition:
		out, err := n.H.Arithmetic().Neg(n.H.Unwrap())
		if err != nil {
			return *new(E), errs.WrapFailed(err, "couldn't negate int")
		}
		return out, nil
	case integer.Multiplication:
		out, err := n.H.Arithmetic().Inverse(n.H.Unwrap())
		if err != nil {
			return *new(E), errs.WrapFailed(err, "couldn't invert int")
		}
		return out, nil
	default:
		return *new(E), errs.NewType("operator (%s) is not supported", with)
	}
}

func (n *Int_[S, E]) GCD(x E) (E, error) {
	return n.H.Structure().GCD(n.H.Unwrap(), x)
}

func (n *Int_[S, E]) LCM(x E) (E, error) {
	return n.H.Structure().LCM(n.H.Unwrap(), x)
}

func (n *Int_[S, E]) Abs() E {
	return n.H.Arithmetic().Abs(n.H.Unwrap())
}

func (n *Int_[S, E]) Sqrt() (E, error) {
	out, err := n.H.Arithmetic().Sqrt(n.H.Unwrap())
	if err != nil {
		return *new(E), errs.WrapFailed(err, "could not take integer square root")
	}
	return out, nil
}

func (n *Int_[S, E]) Neg() E {
	out, err := n.Inverse(integer.Addition)
	if err != nil {
		panic(err)
	}
	return out
}
