package schnorr

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type Variant[F any, M any] interface {
	ComputeNonceCommitment(nonceCommitment, partialNonceCommitment curves.Point) curves.Point
	ComputeChallenge(signingSuite types.SigningSuite, nonceCommitment, publicKey curves.Point, message M) (curves.Scalar, error)
	ComputeResponse(nonceCommitment, publicKey curves.Point, nonce, secretKey, challenge curves.Scalar) curves.Scalar
	SerializeSignature(signature *Signature[F, M]) []byte

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
	NewVerifierBuilder() VerifierBuilder[F, M]
}
