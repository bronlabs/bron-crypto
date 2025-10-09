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
}

// **** Positive Natural Numbers ****

type integerSetMethods[E algebra.Element[E]] interface {
	FromCardinal(cardinal.Cardinal) (E, error)
	FromBig(*big.Int) (E, error)
	Iter() iter.Seq[E]
	IterRange(start, end E) iter.Seq[E]
}

type nPlusMethods[E NatPlus[E, ENP, EN, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EN natMethods[EN, ENP, EZ, EU], EZ intMethods[EZ, ENP, EN, EZ, EU], EU uintMethods[EU, ENP, EN, EZ, EU]] interface {
	algebra.NPlusLike[E]
	integerSetMethods[E]
	base.BoundedFromBelow[E]
	Random(lowInclusive, highExclusive E, prng io.Reader) (E, error)
}

type NPlus[E NatPlus[E, ENP, EN, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EN natMethods[EN, ENP, EZ, EU], EZ intMethods[EZ, ENP, EN, EZ, EU], EU uintMethods[EU, ENP, EN, EZ, EU]] interface {
	nPlusMethods[E, ENP, EN, EZ, EU]
	FromUint64(uint64) (E, error)
	FromNat(EN) (E, error)
	FromInt(EZ) (E, error)
}

type natPlusMethods[E interface {
	algebra.NatPlusLike[E]
}, ENP algebra.NatPlusLike[ENP], EZ algebra.IntLike[EZ], EU algebra.UintLike[EU]] interface {
	algebra.NatPlusLike[E]
	base.Comparable[E]
	LiftableToZ[EZ]

	algebra.LeftBitwiseShiftable[E]
	algebra.RightBitwiseShiftable[E]

	Increment() E

	Big() *big.Int
	Cardinal() cardinal.Cardinal

	Bit(i uint) byte
	TrueLen() uint
	AnnouncedLen() uint

	fmt.Stringer
}

type NatPlus[E natPlusMethods[E, ENP, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EN natMethods[EN, ENP, EZ, EU], EZ intMethods[EZ, ENP, EN, EZ, EU], EU uintMethods[EU, ENP, EN, EZ, EU]] interface {
	natPlusMethods[E, ENP, EZ, EU]
	base.BoundedFromBelowElement
	Decrement() (E, error)
	Nat() EN
	IsUnit(ENP) bool
	Mod(ENP) EU
}

// type natPlusCapMethods[E natPlusMethods[E, ENP, EZ, EU], ENP algebra.NatPlusLike[ENP], EZ algebra.IntLike[EZ], EU algebra.UintLike[EU]] interface {
// 	natPlusMethods[E, ENP, EZ, EU]

// 	algebra.ResizableCapacity[E]
// 	algebra.FixedCapacityOperand[E]
// 	algebra.FixedCapacityDualOperand[E]
// 	algebra.FixedCapacitySummand[E]
// 	algebra.FixedCapacityMultiplicand[E]
// 	algebra.MaybeFixedCapacityDividend[E]
// 	algebra.FixedLengthLeftBitwiseShiftable[E]
// 	algebra.FixedLengthRightBitwiseShiftable[E]

// 	Bit(i uint) byte
// 	TrueLen() uint
// 	AnnouncedLen() uint
// }

// type NatPlusCap[E natPlusCapMethods[E, ENP, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EN natMethods[EN, ENP, EZ, EU], EZ intMethods[EZ, ENP, EN, EZ, EU], EU uintMethods[EU, ENP, EN, EZ, EU]] interface {
// 	NatPlus[E, ENP, EN, EZ, EU]
// 	natPlusCapMethods[E, ENP, EZ, EU]
// }

// *** Natural Numbers ***

type nMethods[E Nat[E, ENP, EN, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EN natMethods[EN, ENP, EZ, EU], EZ intMethods[EZ, ENP, EN, EZ, EU], EU uintMethods[EU, ENP, EN, EZ, EU]] interface {
	algebra.NLike[E]
	integerSetMethods[E]
	base.BoundedFromBelow[E]
	Random(lowInclusive, highExclusive E, prng io.Reader) (E, error)
}

type N[E Nat[E, ENP, EN, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EN natMethods[EN, ENP, EZ, EU], EZ intMethods[EZ, ENP, EN, EZ, EU], EU uintMethods[EU, ENP, EN, EZ, EU]] interface {
	nMethods[E, ENP, EN, EZ, EU]
	FromUint64(uint64) E
	FromNatPlus(ENP) (E, error)
	FromInt(EZ) (E, error)
}

type natMethods[E interface {
	algebra.NatLike[E]
	natPlusMethods[E, ENP, EZ, EU]
}, ENP algebra.NatPlusLike[ENP], EZ algebra.IntLike[EZ], EU algebra.UintLike[EU]] interface {
	algebra.NatLike[E]
	natPlusMethods[E, ENP, EZ, EU]
	Coprime(E) bool
}

type Nat[E natMethods[E, ENP, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EN natMethods[EN, ENP, EZ, EU], EZ intMethods[EZ, ENP, EN, EZ, EU], EU uintMethods[EU, ENP, EN, EZ, EU]] interface {
	natMethods[E, ENP, EZ, EU]
	Decrement() (E, error)
	IsUnit(ENP) bool
	Mod(ENP) EU
	base.BoundedFromBelowElement
}

// type natCapMethods[E interface {
// 	natMethods[E, ENP, EZ, EU]
// 	natPlusCapMethods[E, ENP, EZ, EU]
// }, ENP algebra.NatPlusLike[ENP], EZ algebra.IntLike[EZ], EU algebra.UintLike[EU]] interface {
// 	natMethods[E, ENP, EZ, EU]
// 	natPlusCapMethods[E, ENP, EZ, EU]
// 	algebra.MaybeFixedCapacityMinuend[E]
// 	EuclideanDivCap(E, algebra.Capacity) (quot E, rem E, err error)
// }

// type NatCap[E natCapMethods[E, ENP, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EN natMethods[EN, ENP, EZ, EU], EZ intMethods[EZ, ENP, EN, EZ, EU], EU uintMethods[EU, ENP, EN, EZ, EU]] interface {
// 	Nat[E, ENP, EN, EZ, EU]
// 	base.BoundedFromBelow[E]
// 	natCapMethods[E, ENP, EZ, EU]
// }

// *** Integers ***

type zMethods[E Int[E, ENP, EN, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EN natMethods[EN, ENP, EZ, EU], EZ Int[EZ, ENP, EN, EZ, EU], EU uintMethods[EU, ENP, EN, EZ, EU]] interface {
	algebra.ZLike[E]
	integerSetMethods[E]
	Random(lowInclusive, highExclusive E, prng io.Reader) (E, error)
}

type Z[E Int[E, ENP, EN, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EN natMethods[EN, ENP, EZ, EU], EZ Int[EZ, ENP, EN, EZ, EU], EU uintMethods[EU, ENP, EN, EZ, EU]] interface {
	zMethods[E, ENP, EN, EZ, EU]
	FromUint64(uint64) E
	FromInt64(int64) E
	FromNatPlus(ENP) (E, error)
	FromNat(EN) (E, error)
	FromUint(EU) (E, error)
	FromUintSymmetric(EU) (E, error)
}

type intMethods[E interface {
	algebra.IntLike[E]
	natMethods[E, ENP, EZ, EU]
	Abs() EN
	Decrement() E
}, ENP algebra.NatPlusLike[ENP], EN algebra.NatLike[EN], EZ algebra.IntLike[EZ], EU algebra.UintLike[EU]] interface {
	algebra.IntLike[E]
	natMethods[E, ENP, EZ, EU]
	Abs() EN
	Decrement() E
}

type Int[E intMethods[E, ENP, EN, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EN natMethods[EN, ENP, EZ, EU], EZ intMethods[EZ, ENP, EN, EZ, EU], EU uintMethods[EU, ENP, EN, EZ, EU]] interface {
	intMethods[E, ENP, EN, EZ, EU]
	IsUnit(ENP) bool
	Mod(ENP) EU
}

// type intCapMethods[E interface {
// 	intMethods[E, ENP, EN, EZ, EU]
// 	natPlusCapMethods[E, ENP, EZ, EU]
// }, ENP algebra.NatPlusLike[ENP], EN algebra.NatLike[EN], EZ algebra.IntLike[EZ], EU algebra.UintLike[EU]] interface {
// 	intMethods[E, ENP, EN, EZ, EU]
// 	natPlusCapMethods[E, ENP, EZ, EU]
// }

// type IntCap[E intCapMethods[E, ENP, EN, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EN natMethods[EN, ENP, EZ, EU], EZ intMethods[EZ, ENP, EN, EZ, EU], EU uintMethods[EU, ENP, EN, EZ, EU]] interface {
// 	Int[E, ENP, EN, EZ, EU]
// 	intCapMethods[E, ENP, EN, EZ, EU]
// }

// *** Variable length Unsigned integers ***

type zModNMethods[E Uint[E, ENP, EN, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EN natMethods[EN, ENP, EZ, EU], EZ intMethods[EZ, ENP, EN, EZ, EU], EU uintMethods[EU, ENP, EN, EZ, EU]] interface {
	algebra.MultiplicativeSemiModule[E, EN]
	algebra.ZModLike[E]
	base.Bounded[E]
	algebra.Quotient[E, ENP, EZ]
	algebra.FiniteStructure[E]
	IsInRange(EN) bool
}

type ZModN[E Uint[E, ENP, EN, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EN natMethods[EN, ENP, EZ, EU], EZ intMethods[EZ, ENP, EN, EZ, EU], EU uintMethods[EU, ENP, EN, EZ, EU]] interface {
	zModNMethods[E, ENP, EN, EZ, EU]
	FromUint64(uint64) (E, error)
	FromInt64(int64) (E, error)
	FromNatPlus(ENP) (E, error)
	FromNat(EN) (E, error)
	FromInt(EZ) (E, error)
}

type uintMethods[E interface {
	algebra.UintLike[E]
	algebra.MultiplicativeSemiModuleElement[E, EN]
	intMethods[E, ENP, EN, EZ, EU]
}, ENP algebra.NatPlusLike[ENP], EN algebra.NatLike[EN], EZ algebra.IntLike[EZ], EU algebra.UintLike[EU]] interface {
	algebra.UintLike[E]
	algebra.MultiplicativeSemiModuleElement[E, EN]
	intMethods[E, ENP, EN, EZ, EU]
	algebra.Residue[E, ENP]
	IsQuadraticResidue() bool
	Sqrt() (E, error)
}

type Uint[E uintMethods[E, ENP, EN, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EN natMethods[EN, ENP, EZ, EU], EZ intMethods[EZ, ENP, EN, EZ, EU], EU uintMethods[EU, ENP, EN, EZ, EU]] interface {
	uintMethods[E, ENP, EN, EZ, EU]
	base.BoundedElement
}

// type uintCapMethods[E interface {
// 	uintMethods[E, ENP, EN, EZ, EU]
// 	intCapMethods[E, ENP, EN, EZ, EU]
// }, ENP algebra.NatPlusLike[ENP], EN algebra.NatLike[EN], EZ algebra.IntLike[EZ], EU algebra.UintLike[EU]] interface {
// 	uintMethods[E, ENP, EN, EZ, EU]
// 	intCapMethods[E, ENP, EN, EZ, EU]
// }

// type UintCap[E uintCapMethods[E, ENP, EN, EZ, EU], ENP natPlusMethods[ENP, ENP, EZ, EU], EN natMethods[EN, ENP, EZ, EU], EZ intMethods[EZ, ENP, EN, EZ, EU], EU uintMethods[EU, ENP, EN, EZ, EU]] interface {
// 	Uint[E, ENP, EN, EZ, EU]
// 	uintCapMethods[E, ENP, EN, EZ, EU]
// }
