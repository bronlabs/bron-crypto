package schnorr

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"hash"
)

type Variant[F any, M any, P curves.Point[P, B, S], B fields.FiniteFieldElement[B], S fields.PrimeFieldElement[S]] interface {
	ComputeNonceCommitment(nonceCommitment, partialNonceCommitment P) P
	ComputeChallenge(hashFunc func() hash.Hash, nonceCommitment, publicKey P, message M) (S, error)
	ComputeResponse(nonceCommitment, publicKey P, nonce, secretKey, challenge S) S
	SerializeSignature(signature *Signature[F, M, P, B, S]) []byte

	// NewVerifierBuilder returns a verifier builder specific to a variant of the Schnorr signature.
	// The reason we need it is twofold:
	// Firstly there are some difference on what a signatures contain, e.g. the Zilliqa signatures contain challenge
	// as the first component (unlike EdDSA or BIP-340), so we follow the Zilliqa spec to verify its signatures
	// whereas for other signatures we verify against R (aka nonce commitment).
	// Secondly the builder allow us to overwrite the R and public key used to compute the challenge
	// which in turn allows us to verify Schnorr partial signatures. That way the same procedure is used to verify
	// both signatures and partial signatures for a specific variant of Schnorr.
	// See:
	//  * https://datatracker.ietf.org/doc/html/rfc8032
	//  * https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
	//  * https://docs.zilliqa.com/whitepaper.pdf
	NewVerifierBuilder() VerifierBuilder[F, M, P, B, S]
}
