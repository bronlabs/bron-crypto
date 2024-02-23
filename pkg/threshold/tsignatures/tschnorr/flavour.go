package tschnorr

import (
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
)

type Flavour interface {
	ComputePartialNonceCommitment(nonceCommitment, partialNonceCommitment curves.Point) curves.Point
	ComputeChallengeBytes(nonceCommitment, publicKey curves.Point, message []byte) []byte
	ComputePartialResponse(nonceCommitment, publicKey curves.Point, partialNonce, partialSecretKey, challenge curves.Scalar) curves.Scalar
}

func NewEdDsaCompatibleFlavour() Flavour {
	return &edDsaCompatible{}
}

func NewTaprootFlavour() Flavour {
	return &taproot{}
}

func NewZilliqaFlavour() Flavour {
	return &zilliqa{}
}

type edDsaCompatible struct {
}

var _ Flavour = (*edDsaCompatible)(nil)

func (*edDsaCompatible) ComputePartialNonceCommitment(_, partialNonceCommitment curves.Point) curves.Point {
	return partialNonceCommitment
}

func (*edDsaCompatible) ComputeChallengeBytes(nonceCommitment, publicKey curves.Point, message []byte) []byte {
	return slices.Concat(nonceCommitment.ToAffineCompressed(), publicKey.ToAffineCompressed(), message)
}

func (*edDsaCompatible) ComputePartialResponse(_, _ curves.Point, partialNonce, partialSecretKey, challenge curves.Scalar) curves.Scalar {
	return partialNonce.Add(challenge.Mul(partialSecretKey))
}

type taproot struct {
}

var _ Flavour = (*taproot)(nil)

func (*taproot) ComputePartialNonceCommitment(nonceCommitment, partialNonceCommitment curves.Point) curves.Point {
	if nonceCommitment.AffineY().IsOdd() {
		return partialNonceCommitment.Neg()
	} else {
		return partialNonceCommitment
	}
}

func (*taproot) ComputeChallengeBytes(nonceCommitment, publicKey curves.Point, message []byte) []byte {
	return slices.Concat(nonceCommitment.ToAffineCompressed()[1:], publicKey.ToAffineCompressed()[1:], message)
}

func (*taproot) ComputePartialResponse(nonceCommitment, publicKey curves.Point, partialNonce, partialSecretKey, challenge curves.Scalar) curves.Scalar {
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

type zilliqa struct{}

var _ Flavour = (*zilliqa)(nil)

func (*zilliqa) ComputePartialNonceCommitment(_, partialNonceCommitment curves.Point) curves.Point {
	return partialNonceCommitment
}

func (*zilliqa) ComputeChallengeBytes(nonceCommitment, publicKey curves.Point, message []byte) []byte {
	return slices.Concat(nonceCommitment.ToAffineCompressed(), publicKey.ToAffineCompressed(), message)
}

func (*zilliqa) ComputePartialResponse(_, _ curves.Point, partialNonce, partialSecretKey, challenge curves.Scalar) curves.Scalar {
	return partialNonce.Sub(challenge.Mul(partialSecretKey))
}
