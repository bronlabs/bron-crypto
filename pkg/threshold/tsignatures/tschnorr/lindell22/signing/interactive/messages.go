package interactive_signing

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	hashcommitments "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
)

type Round1Broadcast struct {
	BigRCommitment hashcommitments.Commitment

	_ ds.Incomparable
}

type Round2Broadcast[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]] struct {
	BigRProof   compiler.NIZKPoKProof
	BigR        P
	BigRWitness hashcommitments.Witness

	_ ds.Incomparable
}
