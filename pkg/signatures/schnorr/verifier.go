package schnorr

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"hash"
)

type VerifierBuilder[V any, M any, P curves.Point[P, B, S], B fields.FiniteFieldElement[B], S fields.PrimeFieldElement[S]] interface {
	WithHashFunc(hashFunc func() hash.Hash) VerifierBuilder[V, M, P, B, S]
	WithPublicKey(key *PublicKey[P, B, S]) VerifierBuilder[V, M, P, B, S]
	WithMessage(message M) VerifierBuilder[V, M, P, B, S]
	WithChallengeCommitment(nonceCommitment P) VerifierBuilder[V, M, P, B, S]
	WithChallengePublicKey(challengePublicKey P) VerifierBuilder[V, M, P, B, S]
	Build() (Verifier[V, M, P, B, S], error)
}

type Verifier[V any, M any, P curves.Point[P, B, S], B fields.FiniteFieldElement[B], S fields.PrimeFieldElement[S]] interface {
	Verify(signature *Signature[V, M, P, B, S]) error
}
