package crtp

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
)

type PairingAlgorithm string

type Variety[E, C any] interface {
	Structure[E]

	FromUncompressed(b []byte) (E, error)
	FromCompressed(b []byte) (E, error)
	BaseStructure() Structure[C]
}

type RationalPoint[E, C any] interface {
	Element[E]

	ToCompressed() []byte
	ToUncompressed() []byte
}

type AlgebraicCurve[P, C any] interface {
	Group[P]
	Variety[P, C]
}

type AlgebraicPoint[P, C any] interface {
	GroupElement[P]
	RationalPoint[P, C]
}

type AffineCurve[P, C any] interface {
	AlgebraicCurve[P, C]
	FromAffine(x, y C) (P, error)
}
type AffinePoint[P, C any] interface {
	AlgebraicPoint[P, C]
	AffineX() (C, error)
	AffineY() (C, error)
}

type EllipticCurve[P, FE, S any] interface {
	AffineCurve[P, FE]
	AbelianGroup[P, S]
	AdditiveModule[P, S]
	Cofactor() Cardinal
}

type EllipticCurvePoint[P, FE, S any] interface {
	AffinePoint[P, FE]
	AbelianGroupElement[P, S]
	AdditiveModuleElement[P, S]
	IsTorsionFree() bool
	ClearCofactor() P
}

type PairingFriendlyCurve[P1, FE1, P2, E, S, DS any] interface {
	EllipticCurve[P1, FE1, S]
	DualStructure() DS

	PairingAlgorithm() PairingAlgorithm
	MultiPair(these []P1, duals []P2) (E, error)
	MultiPairAndInvertDuals(these []P1, duals []P2) (E, error)
}

type PairingFriendlyPoint[P1, FE1, P2, E, S any] interface {
	EllipticCurvePoint[P1, FE1, S]
	InSourceGroup() bool

	Pair(P2) (E, error)
	MultiPair(...P2) (E, error)
	MultiPairAndInvertDuals(...P2) (E, error)
}

type PairingType int

const (
	TypeI   PairingType = 1
	TypeII  PairingType = 2
	TypeIII PairingType = 3
)

type PairingProductEvaluator[g1Point, g2Point, gtElement any] interface {
	Name() PairingAlgorithm
	Type() PairingType
	Add(g1 g1Point, g2 g2Point) error
	AddAndInvG1(g1 g1Point, g2 g2Point) error
	AddAndInvG2(g1 g1Point, g2 g2Point) error
	Result() gtElement
	Check() bool
	Reset()
	base.Equatable[PairingProductEvaluator[g1Point, g2Point, gtElement]]
}
