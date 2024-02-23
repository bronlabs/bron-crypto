package schnorr

import (
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
)

type Variant[F any] interface {
	ComputePartialNonceCommitment(nonceCommitment, partialNonceCommitment curves.Point) curves.Point
	ComputeChallengeBytes(nonceCommitment, publicKey curves.Point, message []byte) []byte
	ComputePartialResponse(nonceCommitment, publicKey curves.Point, partialNonce, partialSecretKey, challenge curves.Scalar) curves.Scalar
	SerializeSignature(signature *Signature[F]) []byte
}

func NewEdDsaCompatibleVariant() Variant[EdDsaCompatibleVariant] {
	return &EdDsaCompatibleVariant{}
}

func NewTaprootVariant() Variant[TaprootVariant] {
	return &TaprootVariant{}
}

func NewZilliqaVariant() Variant[ZilliqaVariant] {
	return &ZilliqaVariant{}
}

type EdDsaCompatibleVariant struct {
}

func (EdDsaCompatibleVariant) ComputePartialNonceCommitment(_, partialNonceCommitment curves.Point) curves.Point {
	return partialNonceCommitment
}

func (EdDsaCompatibleVariant) ComputeChallengeBytes(nonceCommitment, publicKey curves.Point, message []byte) []byte {
	return slices.Concat(nonceCommitment.ToAffineCompressed(), publicKey.ToAffineCompressed(), message)
}

func (EdDsaCompatibleVariant) ComputePartialResponse(_, _ curves.Point, partialNonce, partialSecretKey, challenge curves.Scalar) curves.Scalar {
	return partialNonce.Add(challenge.Mul(partialSecretKey))
}

func (EdDsaCompatibleVariant) SerializeSignature(signature *Signature[EdDsaCompatibleVariant]) []byte {
	return slices.Concat(signature.R.ToAffineCompressed(), bitstring.ReverseBytes(signature.S.Bytes()))
}

type TaprootVariant struct {
}

func (TaprootVariant) ComputePartialNonceCommitment(nonceCommitment, partialNonceCommitment curves.Point) curves.Point {
	if nonceCommitment.AffineY().IsOdd() {
		return partialNonceCommitment.Neg()
	} else {
		return partialNonceCommitment
	}
}

func (TaprootVariant) ComputeChallengeBytes(nonceCommitment, publicKey curves.Point, message []byte) []byte {
	return slices.Concat(nonceCommitment.ToAffineCompressed()[1:], publicKey.ToAffineCompressed()[1:], message)
}

func (TaprootVariant) ComputePartialResponse(nonceCommitment, publicKey curves.Point, partialNonce, partialSecretKey, challenge curves.Scalar) curves.Scalar {
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

func (TaprootVariant) SerializeSignature(signature *Signature[TaprootVariant]) []byte {
	return slices.Concat(signature.R.ToAffineCompressed()[1:], signature.S.Bytes())
}

type ZilliqaVariant struct{}

func (ZilliqaVariant) ComputePartialNonceCommitment(_, partialNonceCommitment curves.Point) curves.Point {
	return partialNonceCommitment
}

func (ZilliqaVariant) ComputeChallengeBytes(nonceCommitment, publicKey curves.Point, message []byte) []byte {
	return slices.Concat(nonceCommitment.ToAffineCompressed(), publicKey.ToAffineCompressed(), message)
}

func (ZilliqaVariant) ComputePartialResponse(_, _ curves.Point, partialNonce, partialSecretKey, challenge curves.Scalar) curves.Scalar {
	return partialNonce.Sub(challenge.Mul(partialSecretKey))
}

func (ZilliqaVariant) SerializeSignature(signature *Signature[ZilliqaVariant]) []byte {
	return slices.Concat(signature.E.Bytes(), signature.S.Bytes())
}
