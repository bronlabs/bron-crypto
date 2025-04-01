package zilliqa

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr"
	"hash"
)

type verifierBuilder struct {
	publicKey          *schnorr.PublicKey[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]
	message            []byte
	nonceCommitment    *k256.Point
	challengePublicKey *k256.Point
}

type verifier struct {
	publicKey          *schnorr.PublicKey[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]
	message            []byte
	nonceCommitment    *k256.Point
	challengePublicKey *k256.Point
}

var _ schnorr.VerifierBuilder[ZilliqaVariant, []byte, *k256.Point, *k256.BaseFieldElement, *k256.Scalar] = (*verifierBuilder)(nil)
var _ schnorr.Verifier[ZilliqaVariant, []byte, *k256.Point, *k256.BaseFieldElement, *k256.Scalar] = (*verifier)(nil)

func (v *verifierBuilder) WithHashFunc(_ func() hash.Hash) schnorr.VerifierBuilder[ZilliqaVariant, []byte, *k256.Point, *k256.BaseFieldElement, *k256.Scalar] {
	return v
}

func (v *verifierBuilder) WithPublicKey(publicKey *schnorr.PublicKey[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]) schnorr.VerifierBuilder[ZilliqaVariant, []byte, *k256.Point, *k256.BaseFieldElement, *k256.Scalar] {
	v.publicKey = publicKey
	return v
}

func (v *verifierBuilder) WithMessage(message []byte) schnorr.VerifierBuilder[ZilliqaVariant, []byte, *k256.Point, *k256.BaseFieldElement, *k256.Scalar] {
	v.message = message
	return v
}

func (v *verifierBuilder) WithChallengeCommitment(partialNonceCommitment *k256.Point) schnorr.VerifierBuilder[ZilliqaVariant, []byte, *k256.Point, *k256.BaseFieldElement, *k256.Scalar] {
	v.nonceCommitment = partialNonceCommitment
	return v
}

func (v *verifierBuilder) WithChallengePublicKey(challengePublicKey *k256.Point) schnorr.VerifierBuilder[ZilliqaVariant, []byte, *k256.Point, *k256.BaseFieldElement, *k256.Scalar] {
	v.challengePublicKey = challengePublicKey
	return v
}

func (v *verifierBuilder) Build() (schnorr.Verifier[ZilliqaVariant, []byte, *k256.Point, *k256.BaseFieldElement, *k256.Scalar], error) {
	return &verifier{
		publicKey:          v.publicKey,
		message:            v.message,
		nonceCommitment:    v.nonceCommitment,
		challengePublicKey: v.challengePublicKey,
	}, nil
}

func (v *verifier) Verify(signature *schnorr.Signature[ZilliqaVariant, []byte, *k256.Point, *k256.BaseFieldElement, *k256.Scalar]) error {
	if v.publicKey == nil || signature == nil || len(v.message) == 0 {
		return errs.NewIsNil("argument is empty")
	}

	if v.publicKey.A == nil {
		return errs.NewFailed("incompatible public key")
	}

	if !v.publicKey.A.IsTorsionFree() {
		return errs.NewValidation("Public Key not in the prime subgroup")
	}

	if signature.E == nil || signature.S == nil {
		return errs.NewFailed("incompatible signature")
	}

	if signature.E.IsZero() || signature.S.IsZero() {
		return errs.NewVerification("invalid E or S value, cannot be zero")
	}

	l := v.publicKey.A.ScalarMul(signature.E)
	r := curve.Generator().ScalarMul(signature.S)
	q := r.Add(l)

	if signature.R != nil && !signature.R.Equal(q) {
		return errs.NewFailed("incompatible signature")
	}

	challengePk := v.challengePublicKey
	if challengePk == nil {
		challengePk = v.publicKey.A
	}
	challengeR := v.nonceCommitment
	if challengeR == nil {
		challengeR = signature.R
	}
	eCheck, err := zilliqaVariantInstance.ComputeChallenge(hashFunc, challengeR, challengePk, v.message)
	if err != nil {
		return errs.WrapFailed(err, "cannot compute challenge")
	}

	if !signature.E.Equal(eCheck) {
		return errs.NewVerification("invalid signature")
	}

	return nil
}
