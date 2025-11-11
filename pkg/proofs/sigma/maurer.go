package sigma

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
)

type FiniteGroup[GE algebra.GroupElement[GE]] interface {
	algebra.Group[GE]
	algebra.FiniteStructure[GE]
}

type OneWayHomomorphism[I algebra.GroupElement[I], P algebra.GroupElement[P]] algebra.Homomorphism[I, P]

type Anchor[I algebra.GroupElement[I], P algebra.GroupElement[P]] interface {
	L() *num.Nat
	// PreImage returns w such that phi(w) == x * L()
	PreImage(x I) (w P)
}

type MaurerWitness[P algebra.GroupElement[P]] interface {
	Witness
	base.Transparent[P]
}

type MaurerStatement[I algebra.GroupElement[I]] interface {
	Statement
	base.Transparent[I]
}

type MaurerState[P algebra.GroupElement[P]] interface {
	State
	base.Transparent[P]
}

type MaurerCommitment[I algebra.GroupElement[I]] interface {
	Commitment
	base.Transparent[I]
}

type MaurerResponse[P algebra.GroupElement[P]] interface {
	Response
	base.Transparent[P]
}

type MaurerProtocol[I algebra.GroupElement[I], P algebra.GroupElement[P], X MaurerStatement[I], W MaurerWitness[P], A MaurerCommitment[I], S MaurerState[P], Z MaurerResponse[P]] interface {
	Protocol[X, W, A, S, Z]

	PreImageGroup() FiniteGroup[P]
	ImageGroup() FiniteGroup[I]
	Phi() OneWayHomomorphism[I, P]
	Anchor() Anchor[I, P]
}
