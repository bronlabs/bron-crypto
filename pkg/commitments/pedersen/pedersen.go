package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
)

// Name identifies the Pedersen commitment scheme.
const Name commitments.Name = "pedersen"

func _[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]]() {
	var (
		_ commitments.GroupHomomorphicScheme[*Key[E, S], *Witness[S], S, *Message[S], S, *Commitment[E, S], E, *Committer[E, S], *Verifier[E, S], algebra.PrimeGroup[E, S]] = &Scheme[E, S]{}
		_ algebra.Actable[*Commitment[E, S], *Message[S]]                                                                                                                   = (*Commitment[E, S])(nil)
	)
}
