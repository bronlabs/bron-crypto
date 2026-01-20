package pedersen

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
)

// VerifierOption is a functional option for configuring verifiers.
type VerifierOption[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] = func(*Verifier[E, S]) error

// Verifier checks Pedersen commitments against provided messages and witnesses.
type Verifier[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	commitments.GenericVerifier[*Committer[E, S], *Witness[S], *Message[S], *Commitment[E, S]]
}
