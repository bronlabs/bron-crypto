package mina

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr"
	"hash"
)

type verifierBuilder struct {
	publicKey          *schnorr.PublicKey[*pasta.PallasPoint, *pasta.PallasBaseFieldElement, *pasta.PallasScalar]
	message            *ROInput
	nonceCommitment    *pasta.PallasPoint
	challengePublicKey *pasta.PallasPoint
	variant            MinaVariant
}

type verifier struct {
	publicKey          *schnorr.PublicKey[*pasta.PallasPoint, *pasta.PallasBaseFieldElement, *pasta.PallasScalar]
	message            *ROInput
	nonceCommitment    *pasta.PallasPoint
	challengePublicKey *pasta.PallasPoint
	variant            MinaVariant
}

var _ schnorr.VerifierBuilder[MinaVariant, *ROInput, *pasta.PallasPoint, *pasta.PallasBaseFieldElement, *pasta.PallasScalar] = (*verifierBuilder)(nil)
var _ schnorr.Verifier[MinaVariant, *ROInput, *pasta.PallasPoint, *pasta.PallasBaseFieldElement, *pasta.PallasScalar] = (*verifier)(nil)

func (v *verifierBuilder) WithHashFunc(_ func() hash.Hash) schnorr.VerifierBuilder[MinaVariant, *ROInput, *pasta.PallasPoint, *pasta.PallasBaseFieldElement, *pasta.PallasScalar] {
	return v
}

func (v *verifierBuilder) WithPublicKey(publicKey *schnorr.PublicKey[*pasta.PallasPoint, *pasta.PallasBaseFieldElement, *pasta.PallasScalar]) schnorr.VerifierBuilder[MinaVariant, *ROInput, *pasta.PallasPoint, *pasta.PallasBaseFieldElement, *pasta.PallasScalar] {
	v.publicKey = publicKey
	return v
}

func (v *verifierBuilder) WithMessage(message *ROInput) schnorr.VerifierBuilder[MinaVariant, *ROInput, *pasta.PallasPoint, *pasta.PallasBaseFieldElement, *pasta.PallasScalar] {
	v.message = message
	return v
}

func (v *verifierBuilder) WithChallengeCommitment(partialNonceCommitment *pasta.PallasPoint) schnorr.VerifierBuilder[MinaVariant, *ROInput, *pasta.PallasPoint, *pasta.PallasBaseFieldElement, *pasta.PallasScalar] {
	v.nonceCommitment = partialNonceCommitment
	return v
}

func (v *verifierBuilder) WithChallengePublicKey(challengePublicKey *pasta.PallasPoint) schnorr.VerifierBuilder[MinaVariant, *ROInput, *pasta.PallasPoint, *pasta.PallasBaseFieldElement, *pasta.PallasScalar] {
	v.challengePublicKey = challengePublicKey
	return v
}

func (v *verifierBuilder) Build() (schnorr.Verifier[MinaVariant, *ROInput, *pasta.PallasPoint, *pasta.PallasBaseFieldElement, *pasta.PallasScalar], error) {
	return &verifier{
		publicKey:          v.publicKey,
		message:            v.message,
		nonceCommitment:    v.nonceCommitment,
		challengePublicKey: v.challengePublicKey,
		variant:            v.variant,
	}, nil
}

// https://github.com/o1-labs/o1js/blob/885b50e60ead596cdcd8dc944df55fd3a4467a0a/src/mina-signer/src/signature.ts#L250
func (v *verifier) Verify(signature *schnorr.Signature[MinaVariant, *ROInput, *pasta.PallasPoint, *pasta.PallasBaseFieldElement, *pasta.PallasScalar]) error {
	if v.publicKey == nil || v.publicKey.A == nil {
		return errs.NewArgument("invalid public key")
	}
	if signature == nil || signature.R == nil || signature.S == nil || signature.R.IsZero() || signature.S.IsZero() {
		return errs.NewVerification("some signature elements are nil/zero")
	}

	challengeR := v.nonceCommitment
	if challengeR == nil {
		challengeR = signature.R
	}
	challengePk := v.challengePublicKey
	if challengePk == nil {
		challengePk = v.publicKey.A
	}

	e, err := v.variant.ComputeChallenge(hashFunc, challengeR, challengePk, v.message)
	if err != nil {
		return errs.WrapFailed(err, "cannot create challenge scalar")
	}

	if signature.E != nil && !signature.E.Equal(e) {
		return errs.NewFailed("incompatible signature")
	}

	// 5. Let R = s⋅G - e⋅P.
	bigR := curve.Generator().ScalarMul(signature.S).Sub(v.publicKey.A.ScalarMul(e))

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
