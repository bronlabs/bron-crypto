package mixins

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/groupoid"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/operator"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/order"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/ring"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/cronokirby/saferith"
)

type HolesNaturalSemiRing[NS integer.NaturalSemiRing[NS, N], N integer.NaturalSemiRingElement[NS, N]] interface {
	ring.HolesFactorialSemiRing[NS, N]
	order.HolesChain[NS, N]

	Arithmetic() integer.Arithmetic[N]
}

type HolesNaturalSemiRingElement[NS integer.NaturalSemiRing[NS, N], N integer.NaturalSemiRingElement[NS, N]] interface {
	ring.HolesFactorialSemiRingElement[NS, N]
	order.HolesChainElement[NS, N]

	Arithmetic() integer.Arithmetic[N]
	Uint64() uint64
}

type HolesNPlus[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]] interface {
	HolesNaturalSemiRing[NS, N]
	order.HolesLowerBoundedOrderTheoreticLattice[NS, N]

	Successor() algebra.Successor[N]
}

type HolesNatPlus[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]] interface {
	HolesNaturalSemiRingElement[NS, N]
	order.HolesLowerBoundedOrderTheoreticLatticeElement[NS, N]
}

type HolesNaturalRig[NS integer.NaturalRig[NS, N], N integer.NaturalRigElement[NS, N]] interface {
	HolesNaturalSemiRing[NS, N]
	ring.HolesEuclideanRig[NS, N]
}

type HolesNaturalRigElement[NS integer.NaturalRig[NS, N], N integer.NaturalRigElement[NS, N]] interface {
	HolesNaturalSemiRingElement[NS, N]
	ring.HolesEuclideanRigElement[NS, N]
}

type HolesN[NS integer.N[NS, N], N integer.Nat[NS, N]] interface {
	HolesNaturalRig[NS, N]
	HolesNPlus[NS, N]
}

type HolesNat[NS integer.N[NS, N], N integer.Nat[NS, N]] interface {
	HolesNaturalRigElement[NS, N]
	HolesNatPlus[NS, N]
}

type HolesZ[NS integer.Z[NS, N], N integer.Int[NS, N]] interface {
	HolesNaturalRig[NS, N]
	ring.HolesEuclideanDomain[NS, N]
}

type HolesInt[NS integer.Z[NS, N], N integer.Int[NS, N]] interface {
	HolesNaturalRigElement[NS, N]
	ring.HolesEuclideanDomainElement[NS, N]
}

type HolesZn[S integer.Zn[S, E], E integer.Uint[S, E]] interface {
	groupoid.HolesGroupoid[S, E]
	group.HolesAdditiveGroup[S, E]
	HolesNaturalRig[S, E]
	order.HolesBoundedOrderTheoreticLattice[S, E]

	ModularArithmetic() integer.ModularArithmetic[E]
}

type HolesUint[S integer.Zn[S, E], E integer.Uint[S, E]] interface {
	HolesInt[S, E]
	order.HolesBoundedOrderTheoreticLatticeElement[S, E]
	ring.HolesFiniteRingElement[S, E]

	ModularArithmetic() integer.ModularArithmetic[E]
}

type HolesZp[S integer.Zp[S, E], E integer.IntP[S, E]] interface {
	groupoid.HolesGroupoid[S, E]
	group.HolesMultiplicativeGroup[S, E]
	HolesZn[S, E]
}

type HolesIntP[S integer.Zp[S, E], E integer.IntP[S, E]] interface {
	HolesUint[S, E]
	group.HolesMultiplicativeGroupElement[S, E]
}

type HolesZnX[G integer.ZnX[G, E], E integer.IntX[G, E]] interface {
	group.HolesMultiplicativeGroup[G, E]
	order.HolesBoundedOrderTheoreticLattice[G, E]
	order.HolesChain[G, E]

	Modulus() *saferith.Modulus
	Contains(x E) bool
}

type HolesIntX[G integer.ZnX[G, E], E integer.IntX[G, E]] interface {
	group.HolesMultiplicativeGroupElement[G, E]
	order.HolesBoundedOrderTheoreticLatticeElement[G, E]
	order.HolesChainElement[G, E]
}

func NewNaturalPreSemiRing[NS integer.NaturalSemiRing[NS, N], N integer.NaturalSemiRingElement[NS, N]](arithmetic integer.Arithmetic[N], H HolesNaturalSemiRing[NS, N]) NaturalSemiRing[NS, N] {
	addition := integer.NewAdditionOperator(arithmetic)
	multiplication := integer.NewMultiplicationOperator(arithmetic)
	b := operator.NewOperatorSuiteBuilder[N]().WithPrimary(addition).WithSecondary(multiplication).Build()
	return NaturalSemiRing[NS, N]{
		FactorialSemiRing: ring.NewFactorialSemiRing(H),
		Chain:             order.NewChain(H),
		OperatorSuite:     b,
		H:                 H,
	}
}

func NewNaturalPreSemiRingElement[NS integer.NaturalSemiRing[NS, N], N integer.NaturalSemiRingElement[NS, N]](H HolesNaturalSemiRingElement[NS, N]) NaturalSemiRingElement[NS, N] {
	return NaturalSemiRingElement[NS, N]{
		FactorialSemiRingElement: ring.NewFactorialSemiRingElement(H),
		ChainElement:             order.NewChainElement(H),
		H:                        H,
	}
}

func NewNPlus[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]](arithmetic integer.Arithmetic[N], H HolesNPlus[NS, N]) NPlus[NS, N] {
	return NPlus[NS, N]{
		NaturalSemiRing:                   NewNaturalPreSemiRing(arithmetic, H),
		LowerBoundedOrderTheoreticLattice: order.NewLowerBoundedOrderTheoreticLattice(H),
		H:                                 H,
	}
}

func NewNatPlus[NS integer.NPlus[NS, N], N integer.NatPlus[NS, N]](H HolesNatPlus[NS, N]) NatPlus[NS, N] {
	return NatPlus[NS, N]{
		NaturalSemiRingElement:                   NewNaturalPreSemiRingElement(H),
		LowerBoundedOrderTheoreticLatticeElement: order.NewLowerBoundedOrderTheoreticLatticeElement(H),
		H:                                        H,
	}
}

func NewNaturalSemiRing[NS integer.NaturalRig[NS, N], N integer.NaturalRigElement[NS, N]](arithmetic integer.Arithmetic[N], H HolesNaturalRig[NS, N]) NaturalRig[NS, N] {
	return NaturalRig[NS, N]{
		NaturalSemiRing: NewNaturalPreSemiRing(arithmetic, H),
		EuclideanRig:    ring.NewEuclideanRig(H),
		H:               H,
	}
}

func NewNaturalSemiRingElement[NS integer.NaturalRig[NS, N], N integer.NaturalRigElement[NS, N]](H HolesNaturalRigElement[NS, N]) NaturalRigElement[NS, N] {
	return NaturalRigElement[NS, N]{
		NaturalSemiRingElement: NewNaturalPreSemiRingElement(H),
		EuclideanRigElement:    ring.NewEuclideanRigElement(H),
		H:                      H,
	}
}

func NewN[S integer.N[S, E], E integer.Nat[S, E]](arithmetic integer.Arithmetic[E], H HolesN[S, E]) N[S, E] {
	return N[S, E]{
		NaturalRig: NewNaturalSemiRing(arithmetic, H),
		NPlus:      NewNPlus(arithmetic, H),
		H:          H,
	}
}

func NewNat_[S integer.N[S, E], E integer.Nat[S, E]](H HolesNat[S, E]) Nat_[S, E] {
	return Nat_[S, E]{
		NaturalRigElement:                        NewNaturalSemiRingElement(H),
		LowerBoundedOrderTheoreticLatticeElement: order.NewLowerBoundedOrderTheoreticLatticeElement(H),
		H:                                        H,
	}
}

func NewZ[S integer.Z[S, E], E integer.Int[S, E]](arithmetic integer.Arithmetic[E], H HolesZ[S, E]) Z[S, E] {
	return Z[S, E]{
		Groupoid:         groupoid.NewGroupoid(H),
		AdditiveGroupoid: groupoid.NewAdditiveGroupoid(H),
		AdditiveGroup:    group.NewAdditiveGroup(H),
		NaturalRig:       NewNaturalSemiRing(arithmetic, H),
		H:                H,
	}
}

func NewInt_[S integer.Z[S, E], E integer.Int[S, E]](H HolesInt[S, E]) Int_[S, E] {
	return Int_[S, E]{
		NaturalRigElement:       NewNaturalSemiRingElement(H),
		GroupoidElement:         groupoid.NewGroupoidElement(H),
		AdditiveGroupoidElement: groupoid.NewAdditiveGroupoidElement(H),
		AdditiveGroupElement:    group.NewAdditiveGroupElement(H),
		H:                       H,
	}
}

func NewZn[S integer.Zn[S, E], E integer.Uint[S, E]](arithmetic integer.Arithmetic[E], H HolesZn[S, E]) Zn[S, E] {
	return Zn[S, E]{
		Groupoid:                     groupoid.NewGroupoid(H),
		NaturalRig:                   NewNaturalSemiRing(arithmetic, H),
		BoundedOrderTheoreticLattice: order.NewBoundedOrderTheoreticLattice(H),
		wrappedS: wrappedS[S, E]{
			AdditiveGroup: group.NewAdditiveGroup(H),
		},
		H: H,
	}
}

func NewUint[S integer.Zn[S, E], E integer.Uint[S, E]](H HolesUint[S, E]) Uint[S, E] {
	return Uint[S, E]{
		Int_:                                NewInt_(H),
		BoundedOrderTheoreticLatticeElement: order.NewBoundedOrderTheoreticLatticeElement(H),
		wrappedE: wrappedE[S, E]{
			FiniteRingElement: ring.NewFiniteRingElement(H),
		},
		H: H,
	}
}

func NewZp[S integer.Zp[S, E], E integer.IntP[S, E]](arithmetic integer.Arithmetic[E], H HolesZp[S, E]) Zp[S, E] {
	return Zp[S, E]{
		Groupoid:            groupoid.NewGroupoid(H),
		Zn:                  NewZn(arithmetic, H),
		MultiplicativeGroup: group.NewMultiplicativeGroup(H),
		H:                   H,
	}
}

func NewIntP[S integer.Zp[S, E], E integer.IntP[S, E]](H HolesIntP[S, E]) IntP[S, E] {
	return IntP[S, E]{
		Uint: NewUint(H),
		wrapped: wrapped[S, E]{
			MultiplicativeGroupElement: group.NewMultiplicativeGroupElement(H),
		},
		H: H,
	}
}

func NewZnX[G integer.ZnX[G, E], E integer.IntX[G, E]](arithmetic integer.ModularArithmetic[E], H HolesZnX[G, E]) ZnX[G, E] {
	multiplication := integer.NewMultiplicationOperator(arithmetic)
	suite := operator.NewOperatorSuiteBuilder[E]().WithPrimary(multiplication).Build()
	return ZnX[G, E]{
		Groupoid:                     groupoid.NewGroupoid(H),
		MultiplicativeGroup:          group.NewMultiplicativeGroup(H),
		Chain:                        order.NewChain(H),
		BoundedOrderTheoreticLattice: order.NewBoundedOrderTheoreticLattice(H),
		OperatorSuite:                suite,
		arithmetic:                   arithmetic,
	}
}

func NewIntX[G integer.ZnX[G, E], E integer.IntX[G, E]](arithmetic integer.ModularArithmetic[E], H HolesIntX[G, E]) IntX[G, E] {
	return IntX[G, E]{
		GroupoidElement:                     groupoid.NewGroupoidElement(H),
		MultiplicativeGroupElement:          group.NewMultiplicativeGroupElement(H),
		ChainElement:                        order.NewChainElement(H),
		BoundedOrderTheoreticLatticeElement: order.NewBoundedOrderTheoreticLatticeElement(H),
		arithmetic:                          arithmetic,
	}
}
