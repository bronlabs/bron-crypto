package fields

import "io"

type fieldElement[FP any] interface {
	Set(v FP)
	SetZero()
	SetOne()
	Select(choice uint64, z, nz FP)

	Add(lhs, rhs FP)
	Sub(lhs, rhs FP)
	Neg(v FP)
	Mul(lhs, rhs FP)
	Square(v FP)
	Inv(v FP) (ok uint64)
	Div(lhs, rhs FP) (ok uint64)
	Sqrt(v FP) (ok uint64)

	Equals(rhs FP) uint64
	IsNonZero() uint64
	IsZero() uint64
	IsOne() uint64
}

type FieldElement[FP fieldElement[FP]] interface {
	fieldElement[FP]
}

type FieldElementPtrConstraint[FP fieldElement[FP], F any] interface {
	*F
	fieldElement[FP]
}

type finiteFieldElement[FP fieldElement[FP]] interface {
	fieldElement[FP]

	SetUniformBytes(componentsData ...[]byte) (ok uint64)
	SetRandom(prng io.Reader) (ok uint64)

	ComponentsBytes() [][]byte
	Degree() uint64
}

type FiniteFieldElement[FP finiteFieldElement[FP]] interface {
	finiteFieldElement[FP]
}

type FiniteFieldElementPtrConstraint[FP finiteFieldElement[FP], F any] interface {
	FieldElementPtrConstraint[FP, F]
	finiteFieldElement[FP]
}

type primeFieldElement[PF finiteFieldElement[PF]] interface {
	finiteFieldElement[PF]

	SetUint64(u uint64)
	SetLimbs(data []uint64) (ok uint64)
	SetBytes(data []byte) (ok uint64)
	SetBytesWide(data []byte) (ok uint64)

	Bytes() []byte
	Limbs() []uint64
}

type PrimeFieldElement[FP primeFieldElement[FP]] interface {
	primeFieldElement[FP]
}

type PrimeFieldElementPtrConstraint[FP primeFieldElement[FP], F any] interface {
	FiniteFieldElementPtrConstraint[FP, F]
	primeFieldElement[FP]
}
