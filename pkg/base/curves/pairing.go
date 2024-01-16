package curves

import (
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
)

type PairingCurve interface {
	Name() string
	EmbeddingDegree() *saferith.Nat

	G1() Curve
	G2() Curve
	Gt() Gt

	Pair(pG1, pG2 PairingPoint) (GtMember, error)
	MultiPair(...PairingPoint) (GtMember, error)
}

type PairingPoint interface {
	Point
	PairingCurve() PairingCurve
	OtherPrimeAlgebraicSubGroup() Curve
	Pair(p PairingPoint) GtMember
}

type Gt interface {
	algebra.AbstractGroup[Gt, GtMember]
	algebra.MultiplicativeGroupTrait[Gt, GtMember]
}

type GtMember interface {
	algebra.AbstractGroupElement[Gt, GtMember]
	algebra.MultiplicativeGroupElementTrait[Gt, GtMember]
	Gt() Gt

	SetBytes(bytes []byte) (GtMember, error)
	SetBytesWide(bytes []byte) (GtMember, error)
	Bytes() []byte
}
