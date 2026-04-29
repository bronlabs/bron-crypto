package pedersen_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
)

func _[E pedersen.FiniteAbelianGroupElement[E, S], S algebra.RingElement[S]]() {
	var (
		_ commitments.GroupHomomorphicScheme[
			*pedersen.Key[E, S],
			*pedersen.Witness[S], S,
			*pedersen.Message[S], S,
			*pedersen.Commitment[E, S], E,
			*pedersen.Committer[E, S],
			*pedersen.Verifier[E, S],
			pedersen.FiniteAbelianGroup[E, S],
		] = (*pedersen.Scheme[E, S])(nil)

		_ commitments.EquivocableScheme[
			*pedersen.Key[E, S],
			*pedersen.Trapdoor[E, S],
			*pedersen.Witness[S],
			*pedersen.Message[S],
			*pedersen.Commitment[E, S],
			*pedersen.Committer[E, S],
			*pedersen.Verifier[E, S],
		] = (*pedersen.EquivocableScheme[E, S])(nil)

		_ algebra.Actable[*pedersen.Commitment[E, S], *pedersen.Message[S]] = (*pedersen.Commitment[E, S])(nil)
	)
}
