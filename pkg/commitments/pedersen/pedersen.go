package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
)

const Name commitments.Name = "pedersen"

func _[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]]() {
	var (
		_ commitments.HomomorphicScheme[*Witness[S], S, *Message[S], S, *Commitment[E, S], E] = (*Scheme[E, S])(nil)
		_ algebra.Actable[*Commitment[E, S], *Message[S]]                                     = (*Commitment[E, S])(nil)
	)
}
