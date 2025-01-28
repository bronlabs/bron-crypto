package fields

import "io"

type field[FP any] interface {
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

type Field[FP field[FP]] interface {
	field[FP]
}

type FieldPtrConstraint[FP field[FP], F any] interface {
	*F
	field[FP]
}

type finiteField[FP field[FP]] interface {
	field[FP]

	SetUniformBytes(componentsData ...[]byte) (ok uint64)
	SetRandom(prng io.Reader) (ok uint64)

	ComponentsBytes() [][]byte
	Degree() uint64
}

type FiniteField[FP finiteField[FP]] interface {
	finiteField[FP]
}

type FiniteFieldPtrConstraint[FP finiteField[FP], F any] interface {
	FieldPtrConstraint[FP, F]
	finiteField[FP]
}

type primeField[PF finiteField[PF]] interface {
	finiteField[PF]

	SetUint64(u uint64)
	SetLimbs(data []uint64) (ok uint64)
	SetBytes(data []byte) (ok uint64)
	SetBytesWide(data []byte) (ok uint64)

	Bytes() []byte
	Limbs() []uint64
}

type PrimeField[FP primeField[FP]] interface {
	primeField[FP]
}

type PrimeFieldPtrConstraint[FP primeField[FP], F any] interface {
	FiniteFieldPtrConstraint[FP, F]
	primeField[FP]
}
