package bip340

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

var _ schnorr.VerifierBuilder[TaprootVariant, []byte, *k256.Point, *k256.BaseFieldElement, *k256.Scalar] = (*verifierBuilder)(nil)
var _ schnorr.Verifier[TaprootVariant, []byte, *k256.Point, *k256.BaseFieldElement, *k256.Scalar] = (*verifier)(nil)

func (v *verifierBuilder) WithHashFunc(_ func() hash.Hash) schnorr.VerifierBuilder[TaprootVariant, []byte, *k256.Point, *k256.BaseFieldElement, *k256.Scalar] {
	return v
}

func (v *verifierBuilder) WithPublicKey(publicKey *schnorr.PublicKey[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]) schnorr.VerifierBuilder[TaprootVariant, []byte, *k256.Point, *k256.BaseFieldElement, *k256.Scalar] {
	v.publicKey = publicKey
	return v
}

func (v *verifierBuilder) WithMessage(message []byte) schnorr.VerifierBuilder[TaprootVariant, []byte, *k256.Point, *k256.BaseFieldElement, *k256.Scalar] {
	v.message = message
	return v
}

func (v *verifierBuilder) WithChallengeCommitment(partialNonceCommitment *k256.Point) schnorr.VerifierBuilder[TaprootVariant, []byte, *k256.Point, *k256.BaseFieldElement, *k256.Scalar] {
	v.nonceCommitment = partialNonceCommitment
	return v
}

func (v *verifierBuilder) WithChallengePublicKey(challengePublicKey *k256.Point) schnorr.VerifierBuilder[TaprootVariant, []byte, *k256.Point, *k256.BaseFieldElement, *k256.Scalar] {
	v.challengePublicKey = challengePublicKey
	return v
}

func (v *verifierBuilder) Build() (schnorr.Verifier[TaprootVariant, []byte, *k256.Point, *k256.BaseFieldElement, *k256.Scalar], error) {
	return &verifier{
		publicKey:          v.publicKey,
		message:            v.message,
		nonceCommitment:    v.nonceCommitment,
		challengePublicKey: v.challengePublicKey,
	}, nil
}

func (v *verifier) Verify(signature *schnorr.Signature[TaprootVariant, []byte, *k256.Point, *k256.BaseFieldElement, *k256.Scalar]) error {
	if v.publicKey == nil || v.publicKey.A == nil {
		return errs.NewArgument("curve not supported")
	}
	if signature == nil || signature.R == nil || signature.S == nil || signature.R.IsZero() || signature.S.IsZero() {
		return errs.NewVerification("some signature elements are nil/zero")
	}

	// 1. Let P = lift_x(int(pk)).
	// 2. (implicit) Let r = int(sig[0:32]); fail if r ≥ p.
	// 3. (implicit) Let s = int(sig[32:64]); fail if s ≥ n.
	bigP := v.publicKey.A
	challengePk := v.challengePublicKey
	if challengePk == nil {
		challengePk = v.publicKey.A
	}
	if challengePk.AffineY().IsOdd() {
		challengePk = challengePk.Neg()
		bigP = bigP.Neg()
	}

	// 4. Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
	challengeR := v.nonceCommitment
	if challengeR == nil {
		challengeR = signature.R
	}
	e, err := taprootVariant.ComputeChallenge(hashFunc, challengeR, challengePk, v.message)
	if err != nil {
		return errs.WrapFailed(err, "cannot create challenge scalar")
	}

	if signature.E != nil && !signature.E.Equal(e) {
		return errs.NewFailed("incompatible signature")
	}

	// 5. Let R = s⋅G - e⋅P.
	bigR := curve.Generator().ScalarMul(signature.S).Sub(bigP.ScalarMul(e))

	// 6. Fail if is_infinite(R).
	// 7. Fail if not has_even_y(R).
	// 8. Fail if x(R) ≠ r.
	if !signature.R.AffineX().Equal(bigR.AffineX()) || bigR.IsZero() {
		return errs.NewVerification("signature is invalid")
	}

	if challengeR.Equal(signature.R) && !bigR.AffineY().IsEven() {
		return errs.NewVerification("signature is invalid")
	}

	return nil
}
