package mina

import (
	"slices"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/pallas"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/hashing/poseidon"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/schnorr"
)

var (
	_ schnorr.Variant[MinaVariant, *ROInput] = (*MinaVariant)(nil)
)

//nolint:revive // keep consistency
type MinaVariant struct {
	NetworkId NetworkId
}

func NewMinaVariant(networkId NetworkId) *MinaVariant {
	return &MinaVariant{NetworkId: networkId}
}

func (MinaVariant) ComputeNonceCommitment(nonceCommitment, partialNonceCommitment curves.Point) curves.Point {
	if nonceCommitment.AffineY().IsOdd() {
		return partialNonceCommitment.Neg()
	} else {
		return partialNonceCommitment
	}
}

// https://github.com/o1-labs/o1js/blob/885b50e60ead596cdcd8dc944df55fd3a4467a0a/src/mina-signer/src/signature.ts#L242
func (v MinaVariant) ComputeChallenge(suite types.SigningSuite, nonceCommitment, publicKey curves.Point, message *ROInput) (curves.Scalar, error) {
	if suite != nil {
		if suite.Curve().Name() != curveName {
			return nil, errs.NewFailed("unsupported curve")
		}
		if _, ok := (suite.Hash()()).(*poseidon.Poseidon); !ok {
			return nil, errs.NewFailed("unsupported hash")
		}
	}

	pallasPublicKey, ok := publicKey.(*pallas.Point)
	if !ok {
		return nil, errs.NewType("given public key is not a pallas point")
	}
	pallasR, ok := nonceCommitment.(*pallas.Point)
	if !ok {
		return nil, errs.NewType("given nonceCommitment is not a pallas point")
	}

	input := message.Clone()
	input.AddFields(pallasPublicKey.AffineX())
	input.AddFields(pallasPublicKey.AffineY())
	input.AddFields(pallasR.AffineX())

	prefix := SignaturePrefix(v.NetworkId)
	e, err := hashWithPrefix(prefix, input.PackToFields()...)
	if err != nil {
		return nil, errs.WrapHashing(err, "could not produce challenge")
	}
	return e, nil
}

func (MinaVariant) ComputeResponse(nonceCommitment, _ curves.Point, partialNonce, partialSecretKey, challenge curves.Scalar) curves.Scalar {
	k := partialNonce
	if nonceCommitment.AffineY().IsOdd() {
		k = partialNonce.Neg()
	}

	return k.Add(challenge.Mul(partialSecretKey))
}

func (MinaVariant) SerializeSignature(signature *schnorr.Signature[MinaVariant, *ROInput]) []byte {
	rx := signature.R.AffineX().Bytes()
	s := signature.S.Bytes()
	return slices.Concat(rx, s)
}
func (v MinaVariant) NewVerifierBuilder() schnorr.VerifierBuilder[MinaVariant, *ROInput] {
	return &verifierBuilder{
		variant: v,
	}
}

// https://github.com/o1-labs/o1js/blob/885b50e60ead596cdcd8dc944df55fd3a4467a0a/src/lib/provable/crypto/hash-generic.ts#L23
func hashWithPrefix(prefix Prefix, inputs ...curves.BaseFieldElement) (curves.Scalar, error) {
	h := poseidon.NewLegacy()

	// salt
	pfe, err := prefix.ToBaseFieldElement()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not convert prefix to base field element")
	}
	h.Update(pfe)

	// hashWithPrefix itself
	h.Update(inputs...)

	outBfe, ok := h.Digest().(*pallas.BaseFieldElement)
	if !ok {
		return nil, errs.NewType("output of poseidon is not a valid pallas base field element")
	}

	s, err := pallas.NewScalarField().Element().SetBytes(outBfe.Bytes())
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot deserialize scalar")
	}

	return s, nil
}
