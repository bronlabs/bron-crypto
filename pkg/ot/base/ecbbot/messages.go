package ecbbot

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

// Round1P2P carries the sender's initial key-agreement message mS.
type Round1P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	Ms G `cbor:"ms"` // mS ∈ Point
}

func (*Round1P2P[G, S]) Validate(*participant[G, S]) error { return nil }

// Round2P2P carries the POPF programs derived by the receiver.
type Round2P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	Phi [][2][]G `cbor:"phi"` // Φ ∈ [ξ][2][L]Point
}

func (*Round2P2P[G, S]) Validate(*participant[G, S]) error { return nil }
