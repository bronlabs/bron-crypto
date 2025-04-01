package mina

import (
	"hash"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing/poseidon"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr"
)

var (
	_ schnorr.Variant[MinaVariant, *ROInput, *pasta.PallasPoint, *pasta.PallasBaseFieldElement, *pasta.PallasScalar] = (*MinaVariant)(nil)
)

//nolint:revive // keep consistency
type MinaVariant struct {
	NetworkId NetworkId
}

func NewMinaVariant(networkId NetworkId) *MinaVariant {
	return &MinaVariant{NetworkId: networkId}
}

func (MinaVariant) ComputeNonceCommitment(nonceCommitment, partialNonceCommitment *pasta.PallasPoint) *pasta.PallasPoint {
	if nonceCommitment.AffineY().IsOdd() {
		return partialNonceCommitment.Neg()
	} else {
		return partialNonceCommitment
	}
}

// https://github.com/o1-labs/o1js/blob/885b50e60ead596cdcd8dc944df55fd3a4467a0a/src/mina-signer/src/signature.ts#L242
func (v MinaVariant) ComputeChallenge(hashFunc func() hash.Hash, nonceCommitment, publicKey *pasta.PallasPoint, message *ROInput) (*pasta.PallasScalar, error) {
	if hashFunc == nil {
		return nil, errs.NewFailed("unsupported hash")
	}
	if _, ok := (hashFunc()).(*poseidon.Poseidon); !ok {
		return nil, errs.NewFailed("unsupported hash")
	}

	pallasPublicKey := publicKey
	pallasR := nonceCommitment

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

func (MinaVariant) ComputeResponse(nonceCommitment, _ *pasta.PallasPoint, partialNonce, partialSecretKey, challenge *pasta.PallasScalar) *pasta.PallasScalar {
	k := partialNonce
	if nonceCommitment.AffineY().IsOdd() {
		k = partialNonce.Neg()
	}

	return k.Add(challenge.Mul(partialSecretKey))
}

func (MinaVariant) SerializeSignature(signature *schnorr.Signature[MinaVariant, *ROInput, *pasta.PallasPoint, *pasta.PallasBaseFieldElement, *pasta.PallasScalar]) []byte {
	rx := signature.R.AffineX().Bytes()
	s := signature.S.Bytes()
	return slices.Concat(rx, s)
}
func (v MinaVariant) NewVerifierBuilder() schnorr.VerifierBuilder[MinaVariant, *ROInput, *pasta.PallasPoint, *pasta.PallasBaseFieldElement, *pasta.PallasScalar] {
	return &verifierBuilder{
		variant: v,
	}
}

// https://github.com/o1-labs/o1js/blob/885b50e60ead596cdcd8dc944df55fd3a4467a0a/src/lib/provable/crypto/hash-generic.ts#L23
func hashWithPrefix(prefix Prefix, inputs ...*pasta.PallasBaseFieldElement) (*pasta.PallasScalar, error) {
	h := poseidon.NewLegacy()

	// salt
	pfe, err := prefix.ToBaseFieldElement()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not convert prefix to base field element")
	}
	h.Update(pfe)

	// hashWithPrefix itself
	h.Update(inputs...)

	outBfe := h.Digest()
	s, err := pasta.NewPallasScalarField().FromBytes(outBfe.Bytes())
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot deserialize scalar")
	}

	return s, nil
}
