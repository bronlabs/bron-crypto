package schnorr

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
)

type VerifierBuilder[V any, M any] interface {
	WithSigningSuite(suite types.SigningSuite) VerifierBuilder[V, M]
	WithPublicKey(key *PublicKey) VerifierBuilder[V, M]
	WithMessage(message M) VerifierBuilder[V, M]
	WithChallengeCommitment(nonceCommitment curves.Point) VerifierBuilder[V, M]
	WithChallengePublicKey(challengePublicKey curves.Point) VerifierBuilder[V, M]
	Build() (Verifier[V, M], error)
}

type Verifier[V any, M any] interface {
	Verify(signature *Signature[V, M]) error
}
