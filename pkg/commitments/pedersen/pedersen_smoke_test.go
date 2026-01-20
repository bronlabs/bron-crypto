package pedersen_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
)

func _[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]]() {
	var (
		_ commitments.GroupHomomorphicScheme[
			*pedersen.Key[E, S],
			*pedersen.Witness[S], S,
			*pedersen.Message[S], S,
			*pedersen.Commitment[E, S], E,
			*pedersen.Committer[E, S],
			*pedersen.Verifier[E, S],
			algebra.PrimeGroup[E, S],
		] = (*pedersen.Scheme[E, S])(nil)

		_ commitments.ReRandomisableCommitment[
			*pedersen.Commitment[E, S],
			*pedersen.Witness[S],
			*pedersen.Key[E, S],
		] = (*pedersen.Commitment[E, S])(nil)
	)
}
