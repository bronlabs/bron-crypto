package bip340

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr"
)

type TaprootVariant struct{}

var _ schnorr.Variant[TaprootVariant, []byte] = (*TaprootVariant)(nil)

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

func (TaprootVariant) ComputeChallenge(signingSuite types.SigningSuite, nonceCommitment, publicKey curves.Point, message []byte) (curves.Scalar, error) {
	roinput := slices.Concat(
		nonceCommitment.ToAffineCompressed()[1:],
		publicKey.ToAffineCompressed()[1:],
		message,
	)

	e, err := schnorr.MakeGenericSchnorrChallenge(signingSuite, roinput)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create challenge scalar")
	}
	return e, nil
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

func (TaprootVariant) SerializeSignature(signature *schnorr.Signature[TaprootVariant, []byte]) []byte {
	return slices.Concat(signature.R.ToAffineCompressed()[1:], signature.S.Bytes())
}

func (TaprootVariant) NewVerifierBuilder() schnorr.VerifierBuilder[TaprootVariant, []byte] {
	return &verifierBuilder{}
}
