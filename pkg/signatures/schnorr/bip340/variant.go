package bip340

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"hash"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr"
)

type TaprootVariant struct{}

var _ schnorr.Variant[TaprootVariant, []byte, *k256.Point, *k256.BaseFieldElement, *k256.Scalar] = (*TaprootVariant)(nil)

var taprootVariant = &TaprootVariant{}

func NewTaprootVariant() *TaprootVariant {
	return taprootVariant
}

func (TaprootVariant) ComputeNonceCommitment(nonceCommitment, partialNonceCommitment *k256.Point) *k256.Point {
	y, _ := nonceCommitment.AffineY()
	if y.IsOdd() {
		return partialNonceCommitment.Neg()
	} else {
		return partialNonceCommitment
	}
}

func (TaprootVariant) ComputeChallenge(hashFunc func() hash.Hash, nonceCommitment, publicKey *k256.Point, message []byte) (*k256.Scalar, error) {
	roinput := slices.Concat(
		nonceCommitment.ToAffineCompressed()[1:],
		publicKey.ToAffineCompressed()[1:],
		message,
	)

	e, err := schnorr.MakeGenericSchnorrChallenge(curve.ScalarField(), hashFunc, schnorr.BigEndian, roinput)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create challenge scalar")
	}
	return e, nil
}

func (TaprootVariant) ComputeResponse(nonceCommitment, publicKey *k256.Point, partialNonce, partialSecretKey, challenge *k256.Scalar) *k256.Scalar {
	k := partialNonce
	y, _ := nonceCommitment.AffineY()
	if y.IsOdd() {
		k = partialNonce.Neg()
	}

	sk := partialSecretKey
	y, _ = publicKey.AffineY()
	if y.IsOdd() {
		sk = partialSecretKey.Neg()
	}

	return k.Add(challenge.Mul(sk))
}

func (TaprootVariant) SerializeSignature(signature *schnorr.Signature[TaprootVariant, []byte, *k256.Point, *k256.BaseFieldElement, *k256.Scalar]) []byte {
	return slices.Concat(signature.R.ToAffineCompressed()[1:], signature.S.Bytes())
}

func (TaprootVariant) NewVerifierBuilder() schnorr.VerifierBuilder[TaprootVariant, []byte, *k256.Point, *k256.BaseFieldElement, *k256.Scalar] {
	return &verifierBuilder{}
}
