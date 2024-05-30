package mixins

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/cronokirby/saferith"
)

type Z[S integer.Z[S, E], E integer.Int[S, E]] struct {
	groupoid.Groupoid[S, E]
	groupoid.AdditiveGroupoid[S, E]
	group.AdditiveGroup[S, E]
	NaturalRig[S, E]

	H HolesZ[S, E]
}

func (z *Z[S, E]) Contains(x E) bool {
	return true
}

func (z *Z[S, E]) Characteristic() *saferith.Nat {
	return new(saferith.Nat).SetUint64(0)
}

func (z *Z[S, E]) Iter() <-chan E {
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
	groupoid.GroupoidElement[S, E]
	groupoid.AdditiveGroupoidElement[S, E]
	group.AdditiveGroupElement[S, E]
	NaturalRigElement[S, E]

	H HolesInt[S, E]
}

func (n *Int_[S, E]) Sub(x algebra.AdditiveGroupElement[S, E]) E {
	out, err := n.H.Arithmetic().Sub(n.H.Unwrap(), x.Unwrap(), -1)
	if err != nil {
		panic(errs.WrapFailed(err, "could not sub"))
	}
	return out
}

func (n *Int_[S, E]) Decrement() E {
	return n.Sub(n.H.Structure().One())
}

func (n *Int_[S, E]) Sqrt() (E, error) {
	out, err := n.H.Arithmetic().Sqrt(n.H.Unwrap())
	if err != nil {
		return *new(E), errs.WrapFailed(err, "couldn't take sqrt")
	}
	return out, nil
}

func (n *Int_[S, E]) EuclideanDiv(x E) (E, E) {
	quot, rem, err := n.H.Arithmetic().Div(n.H.Unwrap(), x, -1)
	if err != nil {
		panic(errs.WrapFailed(err, "couldn't take euclidean div"))
	}
	return quot, rem
}

func (n *Int_[S, E]) Abs() E {
	if n.Cmp(n.H.Structure().Zero()) == algebra.LessThan {
		return n.Neg()
	}
	return n.H.Unwrap()
}

func (n *Int_[S, E]) IsUnit() bool {
	return n.Abs().IsOne()
}

func (n *Int_[S, E]) Neg() E {
	out, err := n.H.Arithmetic().Neg(n.H.Unwrap())
	if err != nil {
		panic(errs.WrapFailed(err, "could not negate"))
	}
	return out
}

func (n *Int_[S, E]) AdditiveInverse() E {
	return n.Neg()
}

func (n *Int_[S, E]) Inverse(with algebra.Operator) (E, error) {
	switch with {
	case integer.Addition:
		return n.Neg(), nil
	case integer.Multiplication:
		if n.IsOne() {
			return n.H.Unwrap(), nil
		}
		return *new(E), errs.NewValue("only one has a multiplicative inverse in Z")
	default:
		return *new(E), errs.NewType("operator (%s) is not supported", with)
	}
}
