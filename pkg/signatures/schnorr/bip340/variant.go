package bip340

import (
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
)

type TaprootVariant struct {
}

var _ schnorr.Variant[TaprootVariant] = (*TaprootVariant)(nil)

var taprootVariant = &TaprootVariant{}

func NewTaprootVariant() *TaprootVariant {
	return taprootVariant
}

func (TaprootVariant) ComputeNonceCommitment(nonceCommitment, partialNonceCommitment curves.Point) curves.Point {
	if nonceCommitment.AffineY().IsOdd() {
		return partialNonceCommitment.Neg()
	} else {
		return partialNonceCommitment
	}
}

func (TaprootVariant) ComputeChallengeBytes(nonceCommitment, publicKey curves.Point, message []byte) []byte {
	return slices.Concat(nonceCommitment.ToAffineCompressed()[1:], publicKey.ToAffineCompressed()[1:], message)
}

func (TaprootVariant) ComputeResponse(nonceCommitment, publicKey curves.Point, partialNonce, partialSecretKey, challenge curves.Scalar) curves.Scalar {
	k := partialNonce
	if nonceCommitment.AffineY().IsOdd() {
		k = partialNonce.Neg()
	}

	sk := partialSecretKey
	if publicKey.AffineY().IsOdd() {
		sk = partialSecretKey.Neg()
	}

	return k.Add(challenge.Mul(sk))
}

func (TaprootVariant) SerializeSignature(signature *Signature) []byte {
	return slices.Concat(signature.R.ToAffineCompressed()[1:], signature.S.Bytes())
}

func (TaprootVariant) NewVerifierBuilder() schnorr.VerifierBuilder[TaprootVariant] {
	return &verifierBuilder{}
}
