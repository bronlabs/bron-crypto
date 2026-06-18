package pedersencom_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/pedersencom"
)

func _[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]]() {
	var (
		_ commitments.GroupHomomorphicCommitmentKey[
			*pedersencom.CommitmentKey[E, S],
			*pedersencom.Message[S], algebra.PrimeField[S], S,
			*pedersencom.Witness[S], algebra.PrimeField[S], S,
			*pedersencom.Commitment[E, S], algebra.PrimeGroup[E, S], E,
			S,
		] = (*pedersencom.CommitmentKey[E, S])(nil)

		_ commitments.GroupHomomorphicTrapdoorKey[
			*pedersencom.CommitmentKey[E, S],
			*pedersencom.TrapdoorKey[E, S],
			*pedersencom.Message[S], algebra.PrimeField[S], S,
			*pedersencom.Witness[S], algebra.PrimeField[S], S,
			*pedersencom.Commitment[E, S], algebra.PrimeGroup[E, S], E,
			S,
		] = (*pedersencom.TrapdoorKey[E, S])(nil)
	)
}
