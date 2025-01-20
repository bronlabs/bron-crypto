package fields

import "io"

type fieldPtr[FP any] interface {
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

type FieldPtr[FP fieldPtr[FP]] interface {
	fieldPtr[FP]
}

type FieldPtrConstraint[FP fieldPtr[FP], F any] interface {
	*F
	fieldPtr[FP]
}

type finiteFieldPtr[FP fieldPtr[FP]] interface {
	fieldPtr[FP]

	SetUniformBytes(componentsData ...[]byte) (ok uint64)
	SetRandom(prng io.Reader) (ok uint64)

	ComponentsBytes() [][]byte
	Degree() uint64
}

type FiniteFieldPtr[FP finiteFieldPtr[FP]] interface {
	finiteFieldPtr[FP]
}

type FiniteFieldPtrConstraint[FP finiteFieldPtr[FP], F any] interface {
	FieldPtrConstraint[FP, F]
	finiteFieldPtr[FP]
}

type primeFieldPtr[PF finiteFieldPtr[PF]] interface {
	finiteFieldPtr[PF]

	SetUint64(u uint64)
	SetLimbs(data []uint64) (ok uint64)
	SetBytes(data []byte) (ok uint64)
	SetBytesWide(data []byte) (ok uint64)

	Bytes() []byte
	Limbs() []uint64
}

type PrimeFieldPtr[FP primeFieldPtr[FP]] interface {
	primeFieldPtr[FP]
}

type PrimeFieldPtrConstraint[FP primeFieldPtr[FP], F any] interface {
	FiniteFieldPtrConstraint[FP, F]
	primeFieldPtr[FP]
}
