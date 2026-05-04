package pedersen_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
)

func _[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]]() {
	var (
		_ commitments.GroupHomomorphicCommitmentKey[
			*pedersen.CommitmentKey[E, S],
			*pedersen.Message[S], algebra.PrimeField[S], S,
			*pedersen.Witness[S], algebra.PrimeField[S], S,
			*pedersen.Commitment[E, S], algebra.PrimeGroup[E, S], E,
			S,
		] = (*pedersen.CommitmentKey[E, S])(nil)

		_ commitments.GroupHomomorphicTrapdoorKey[
			*pedersen.CommitmentKey[E, S],
			*pedersen.TrapdoorKey[E, S],
			*pedersen.Message[S], algebra.PrimeField[S], S,
			*pedersen.Witness[S], algebra.PrimeField[S], S,
			*pedersen.Commitment[E, S], algebra.PrimeGroup[E, S], E,
			S,
		] = (*pedersen.TrapdoorKey[E, S])(nil)
	)
}
