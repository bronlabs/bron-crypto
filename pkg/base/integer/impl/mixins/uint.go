package mixins

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/order"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/ring"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
)

type wrappedS[S integer.Zn[S, E], E integer.Uint[S, E]] struct {
	group.AdditiveGroup[S, E]
}

type Zn[S integer.Zn[S, E], E integer.Uint[S, E]] struct {
	groupoid.Groupoid[S, E]
	NaturalRig[S, E]
	order.BoundedOrderTheoreticLattice[S, E]
	wrappedS[S, E]

	H HolesZn[S, E]
}

func (n *Zn[S, E]) Bottom() E {
	return n.Zero()
}
func (n *Zn[S, E]) Top() E {
	return n.Zero().Sub(n.One())
}

func (z *Zn[S, E]) Contains(x E) bool {
	interval := algebra.ClosedInterval[S, E]{
		Left:  z.Bottom(),
		Right: z.Top(),
	}
	return interval.ContainsElement(x)
}

func (z *Zn[S, E]) ElementSize() int {
	panic("implement me")
}

func (z *Zn[S, E]) WideElementSize() int {
	panic("implement me")
}

func (z *Zn[S, E]) Hash(input []byte) (E, error) {
	panic("implement me")
}

func (z *Zn[S, E]) IsDecomposable(factors ...E) bool {
	return len(factors) != 0 && z.CoPrime(factors[0], factors[1:]...)
}

func (z *Zn[S, E]) QuadraticResidue(x algebra.RingElement[S, E]) (E, error) {
	return z.H.ModularArithmetic().QuadraticResidue(x.Unwrap())
}

func (z *Zn[S, E]) Random(prng io.Reader) (E, error) {
	panic("implement me")
}

func (z *Zn[S, E]) Select(choice bool, x0, x1 E) E {
	panic("implement me")
}

func (z *Zn[S, E]) Iter() <-chan E {
	ch := make(chan E, 1)
	go func() {
		current := z.Zero()
		ch <- current
		for algebra.IsLessThan(current, z.Top()) {
			current = current.Increment()
			ch <- current
		}
	}()
	return ch
}

type wrappedE[S integer.Zn[S, E], E integer.Uint[S, E]] struct {
	ring.FiniteRingElement[S, E]
}

type Uint[S integer.Zn[S, E], E integer.Uint[S, E]] struct {
	Int_[S, E]
	order.BoundedOrderTheoreticLatticeElement[S, E]
	wrappedE[S, E]
	H HolesUint[S, E]
}
