package sigma

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
)

// MaurerStatement is a statement with transparent group encoding.
type MaurerStatement[I algebra.GroupElement[I]] interface {
	Statement
	base.Transparent[I]
}

// MaurerWitness is a witness with transparent group encoding.
type MaurerWitness[P algebra.GroupElement[P]] interface {
	Witness
	base.Transparent[P]
}

// MaurerCommitment is a commitment with transparent group encoding.
type MaurerCommitment[I algebra.GroupElement[I]] interface {
	Commitment
	base.Transparent[I]
}

// MaurerState is a prover state with transparent group encoding.
type MaurerState[P algebra.GroupElement[P]] interface {
	State
	base.Transparent[P]
}

// MaurerResponse is a response with transparent group encoding.
type MaurerResponse[P algebra.GroupElement[P]] interface {
	Response
	base.Transparent[P]
}

// OneWayHomomorphism defines the one way group homomorphism used in Maurer-style proofs.
type OneWayHomomorphism[I algebra.GroupElement[I], P algebra.GroupElement[P]] algebra.Homomorphism[I, P]

// Anchor defines the public anchor for Maurer-style protocols.
// I.e., it defines a scalar L for which it is easy to compute phi^{-1}(x * L).
type Anchor[I algebra.GroupElement[I], P algebra.GroupElement[P]] interface {
	L() *num.Nat
	// PreImage returns w such that phi(w) == x * L()
	PreImage(x I) (w P)
}

// MaurerProtocol defines Maurer-style protocol.
type MaurerProtocol[
	I algebra.GroupElement[I],
	P algebra.GroupElement[P],
	X MaurerStatement[I],
	W MaurerWitness[P],
	A MaurerStatement[I],
	S MaurerState[P],
	Z MaurerResponse[P],
] interface {
	Protocol[X, W, A, S, Z]

	PreImageGroup() algebra.FiniteGroup[P]
	ImageGroup() algebra.FiniteGroup[I]
	Phi() OneWayHomomorphism[I, P]
	Anchor() Anchor[I, P]
}
