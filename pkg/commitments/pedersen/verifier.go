package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
)

type Verifier[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	commitments.GenericVerifier[*Committer[E, S], *Witness[S], *Message[S], *Commitment[E, S]]
}
