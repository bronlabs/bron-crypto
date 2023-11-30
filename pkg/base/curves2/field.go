package curves2

import (
	"github.com/cronokirby/saferith"
	"io"
)

type FieldElement interface {
	FromRandom(prng io.Reader) FieldElement
	FromBytes(bytes []byte) FieldElement
	FromHash(bytes []byte) FieldElement
	Clone() FieldElement
	Zero() FieldElement
	One() FieldElement
	Add(rhs FieldElement) FieldElement
	Sub(rhs FieldElement) FieldElement
	Mul(rhs FieldElement) FieldElement
	Div(rhs FieldElement) FieldElement
	Neg(rhs FieldElement) FieldElement
	Inv(rhs FieldElement) FieldElement
	Double() FieldElement
	Triple() FieldElement
	Square() FieldElement
	Cube() FieldElement
	Pow(exp saferith.Nat) FieldElement
	Sqrt() FieldElement
	IsZero() bool
	IsOne() bool
	Bytes() []byte
	Order() saferith.Nat
	Characteristic() saferith.Nat
	ExtensionDegree() saferith.Nat
}

type PrimeFieldElement interface {
	FieldElement

	FromUint64(uint64) PrimeFieldElement
	FromNat(nat saferith.Nat) PrimeFieldElement
	Cmp(rhs PrimeFieldElement) int
	IsEven() bool
	IsOdd() bool
	Nat() saferith.Nat
}
