package sigma

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
)

type OneWayHomomorphism[I algebra.GroupElement[I], P algebra.GroupElement[P]] algebra.Homomorphism[I, P]

type Anchor[I algebra.GroupElement[I], P algebra.GroupElement[P]] interface {
	L() *num.Nat
	// PreImage returns w such that phi(w) == x * L()
	PreImage(x I) (w P)
}

type MaurerProtocol[
	I algebra.GroupElement[I],
	P algebra.GroupElement[P],
	X interface {
		Statement
		base.Transparent[I]
	},
	W interface {
		Witness
		base.Transparent[P]
	},
	A interface {
		Commitment
		base.Transparent[I]
	},
	S interface {
		State
		base.Transparent[P]
	},
	Z interface {
		Response
		base.Transparent[P]
	},
] interface {
	Protocol[X, W, A, S, Z]

	PreImageGroup() algebra.FiniteGroup[P]
	ImageGroup() algebra.FiniteGroup[I]
	Phi() OneWayHomomorphism[I, P]
	Anchor() Anchor[I, P]
}
