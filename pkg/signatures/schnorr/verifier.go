package schnorr

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type VerifierBuilder[V any] interface {
	WithSigningSuite(suite types.SigningSuite) VerifierBuilder[V]
	WithPublicKey(key *PublicKey) VerifierBuilder[V]
	WithMessage(message []byte) VerifierBuilder[V]
	WithChallengeCommitment(nonceCommitment curves.Point) VerifierBuilder[V]
	WithChallengePublicKey(challengePublicKey curves.Point) VerifierBuilder[V]
	Build() Verifier[V]
}

type Verifier[V any] interface {
	Verify(signature *Signature[V]) error
}
