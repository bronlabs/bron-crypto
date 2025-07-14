package internal

import (
	"fmt"
	"io"
	"iter"
	"math/big"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
)

type LiftableToZ[I algebra.IntLike[I]] interface {
	Lift() I
	Abs() I
}

// **** Positive Natural Numbers ****

type integerSetMethods[E algebra.Element[E]] interface {
	FromCardinal(cardinal.Cardinal) (E, error)
	Random(lowInclusive, highExclusive E, prng io.Reader) (E, error)
	Iter() iter.Seq[E]
	IterRange(start, end E) iter.Seq[E]
}

type NPlus[E NatPlus[E, ENP, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EN natMethods[EN, ENP, EZ, EU], EZ intMethods[EZ, ENP, EZ, EU], EU uintMethods[EU, ENP, EZ, EU]] interface {
	algebra.NPlusLike[E]
	integerSetMethods[E]
	algebra.MultiplicativeSemiModule[E, E]
	base.BoundedFromBelow[E]
	FromUint64(uint64) (E, error)
	FromNat(EN) (E, error)
	FromInt(EZ) (E, error)
}

type natPlusMethods[E interface {
	algebra.NatPlusLike[E]
	algebra.MultiplicativeSemiModuleElement[E, E]
}, ENP algebra.NatPlusLike[ENP], EZ algebra.IntLike[EZ], EU algebra.UintLike[EU]] interface {
	algebra.NatPlusLike[E]
	base.Comparable[E]
	algebra.MultiplicativeSemiModuleElement[E, E]
	LiftableToZ[EZ]

	Mod(ENP) (EU, error)
	IsUnit(ENP) bool
	algebra.LeftBitwiseShiftable[E]
	algebra.RightBitwiseShiftable[E]
	algebra.Conjunct[E]
	algebra.Disjunct[E]
	algebra.ExclusiveDisjunct[E]
	algebra.BooleanNegand[E]

	IsInRange(ENP) bool
	Increment()

	Big() *big.Int
	fmt.Stringer
}

type NatPlus[E natPlusMethods[E, ENP, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EZ intMethods[EZ, ENP, EZ, EU], EU uintMethods[EU, ENP, EZ, EU]] interface {
	natPlusMethods[E, ENP, EZ, EU]
	base.BoundedFromBelow[E]
	Decrement() error
}

type natPlusCapMethods[E natPlusMethods[E, ENP, EZ, EU], ENP algebra.NatPlusLike[ENP], EZ algebra.IntLike[EZ], EU algebra.UintLike[EU]] interface {
	natPlusMethods[E, ENP, EZ, EU]

	algebra.ResizableCapacity[E]
	algebra.FixedCapacityOperand[E]
	algebra.FixedCapacityDualOperand[E]
	algebra.FixedCapacitySummand[E]
	algebra.MaybeFixedCapacityMinuend[E]
	algebra.FixedCapacityMultiplicand[E]
	algebra.MaybeFixedCapacityDividend[E]

	Bit(i uint) byte
	TrueLen() uint
	AnnouncedLen() uint
}

type NatPlusCap[E natPlusCapMethods[E, ENP, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EZ intMethods[EZ, ENP, EZ, EU], EU uintMethods[EU, ENP, EZ, EU]] interface {
	NatPlus[E, ENP, EZ, EU]
	natPlusCapMethods[E, ENP, EZ, EU]
}

// *** Natural Numbers ***

type N[E natMethods[E, ENP, EZ, EU], ENP NatPlus[ENP, ENP, EZ, EU], EZ intMethods[EZ, ENP, EZ, EU], EU uintMethods[EU, ENP, EZ, EU]] interface {
	algebra.NLike[E]
	algebra.AdditiveSemiModule[E, E]
	integerSetMethods[E]
	base.BoundedFromBelow[E]
	FromNatPlus(ENP) (E, error)
	FromInt(EZ) (E, error)
}

type natMethods[E interface {
	algebra.NatLike[E]
	algebra.AdditiveSemiModuleElement[E, E]
	natPlusMethods[E, ENP, EZ, EU]
}, ENP algebra.NatPlusLike[ENP], EZ algebra.IntLike[EZ], EU algebra.UintLike[EU]] interface {
	algebra.NatLike[E]
	natPlusMethods[E, ENP, EZ, EU]
	algebra.AdditiveSemiModuleElement[E, E]
	Coprime(E) bool
	Sqrt() (E, error)
}

type Nat[E natMethods[E, ENP, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EZ intMethods[EZ, ENP, EZ, EU], EU uintMethods[EU, ENP, EZ, EU]] interface {
	natMethods[E, ENP, EZ, EU]
	Decrement() error
}

type natCapMethods[E interface {
	natMethods[E, ENP, EZ, EU]
	natPlusCapMethods[E, ENP, EZ, EU]
}, ENP algebra.NatPlusLike[ENP], EZ algebra.IntLike[EZ], EU algebra.UintLike[EU]] interface {
	natMethods[E, ENP, EZ, EU]
	natPlusCapMethods[E, ENP, EZ, EU]
	EuclideanDivCap(E, algebra.Capacity) (quot E, rem E, err error)
}

type NatCap[E natCapMethods[E, ENP, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EZ intMethods[EZ, ENP, EZ, EU], EU uintMethods[EU, ENP, EZ, EU]] interface {
	Nat[E, ENP, EZ, EU]
	base.BoundedFromBelow[E]
	natCapMethods[E, ENP, EZ, EU]
}

// *** Integers ***

type Z[E Int[E, ENP, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EN natMethods[EN, ENP, EZ, EU], EZ Int[EZ, ENP, EZ, EU], EU uintMethods[EU, ENP, EZ, EU]] interface {
	algebra.ZLike[E]
	algebra.Algebra[E, E]
	integerSetMethods[E]
	FromNatPlus(ENP) (E, error)
	FromNat(EN) (E, error)
}

type intMethods[E interface {
	algebra.IntLike[E]
	algebra.AlgebraElement[E, E]
	natMethods[E, ENP, EZ, EU]
	Decrement()
}, ENP algebra.NatPlusLike[ENP], EZ algebra.IntLike[EZ], EU algebra.UintLike[EU]] interface {
	algebra.IntLike[E]
	algebra.AlgebraElement[E, E]
	natMethods[E, ENP, EZ, EU]
	Decrement()
}

type Int[E intMethods[E, ENP, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EZ intMethods[EZ, ENP, EZ, EU], EU uintMethods[EU, ENP, EZ, EU]] intMethods[E, ENP, EZ, EU]

type intCapMethods[E interface {
	intMethods[E, ENP, EZ, EU]
	natPlusCapMethods[E, ENP, EZ, EU]
}, ENP algebra.NatPlusLike[ENP], EZ algebra.IntLike[EZ], EU algebra.UintLike[EU]] interface {
	intMethods[E, ENP, EZ, EU]
	natPlusCapMethods[E, ENP, EZ, EU]
}

type IntCap[E intCapMethods[E, ENP, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EZ intMethods[EZ, ENP, EZ, EU], EU uintMethods[EU, ENP, EZ, EU]] interface {
	Int[E, ENP, EZ, EU]
	intCapMethods[E, ENP, EZ, EU]
}

// *** Variable length Unsigned integers ***

type ZModN[E Uint[E, ENP, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EZ intMethods[EZ, ENP, EZ, EU], EU uintMethods[EU, ENP, EZ, EU]] interface {
	algebra.UintLike[E]
	base.Bounded[E]
	Modulus() ENP
}

type uintMethods[E interface {
	algebra.UintLike[E]
	intMethods[E, ENP, EZ, EU]
}, ENP algebra.NatPlusLike[ENP], EZ algebra.IntLike[EZ], EU algebra.UintLike[EU]] interface {
	algebra.UintLike[E]
	intMethods[E, ENP, EZ, EU]
	EqualModulus(other E) bool
	IsQuadraticResidue() bool
	Modulus() ENP
}

type Uint[E uintMethods[E, ENP, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EZ intMethods[EZ, ENP, EZ, EU], EU uintMethods[EU, ENP, EZ, EU]] uintMethods[E, ENP, EZ, EU]

type uintCapMethods[E interface {
	uintMethods[E, ENP, EZ, EU]
	intCapMethods[E, ENP, EZ, EU]
}, ENP algebra.NatPlusLike[ENP], EZ algebra.IntLike[EZ], EU algebra.UintLike[EU]] interface {
	uintMethods[E, ENP, EZ, EU]
	intCapMethods[E, ENP, EZ, EU]
}

type UintCap[E uintCapMethods[E, ENP, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EZ intMethods[EZ, ENP, EZ, EU], EU uintMethods[EU, ENP, EZ, EU]] interface {
	Uint[E, ENP, EZ, EU]
	uintCapMethods[E, ENP, EZ, EU]
}
