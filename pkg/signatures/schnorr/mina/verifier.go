package mina

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
)

type verifierBuilder struct {
	publicKey          *schnorr.PublicKey
	message            *ROInput
	nonceCommitment    curves.Point
	challengePublicKey curves.Point
	variant            MinaVariant
}

type verifier struct {
	publicKey          *schnorr.PublicKey
	message            *ROInput
	nonceCommitment    curves.Point
	challengePublicKey curves.Point
	variant            MinaVariant
}

var _ schnorr.VerifierBuilder[MinaVariant, *ROInput] = (*verifierBuilder)(nil)
var _ schnorr.Verifier[MinaVariant, *ROInput] = (*verifier)(nil)

func (v *verifierBuilder) WithSigningSuite(_ types.SigningSuite) schnorr.VerifierBuilder[MinaVariant, *ROInput] {
	return v
}

func (v *verifierBuilder) WithPublicKey(publicKey *schnorr.PublicKey) schnorr.VerifierBuilder[MinaVariant, *ROInput] {
	v.publicKey = publicKey
	return v
}

func (v *verifierBuilder) WithMessage(message *ROInput) schnorr.VerifierBuilder[MinaVariant, *ROInput] {
	v.message = message
	return v
}

func (v *verifierBuilder) WithChallengeCommitment(partialNonceCommitment curves.Point) schnorr.VerifierBuilder[MinaVariant, *ROInput] {
	v.nonceCommitment = partialNonceCommitment
	return v
}

func (v *verifierBuilder) WithChallengePublicKey(challengePublicKey curves.Point) schnorr.VerifierBuilder[MinaVariant, *ROInput] {
	v.challengePublicKey = challengePublicKey
	return v
}

func (v *verifierBuilder) Build() (schnorr.Verifier[MinaVariant, *ROInput], error) {
	return &verifier{
		publicKey:          v.publicKey,
		message:            v.message,
		nonceCommitment:    v.nonceCommitment,
		challengePublicKey: v.challengePublicKey,
		variant:            v.variant,
	}, nil
}

// https://github.com/o1-labs/o1js/blob/885b50e60ead596cdcd8dc944df55fd3a4467a0a/src/mina-signer/src/signature.ts#L250
func (v *verifier) Verify(signature *schnorr.Signature[MinaVariant, *ROInput]) error {
	if v.publicKey == nil || v.publicKey.A == nil || v.publicKey.A.Curve().Name() != curveName {
		return errs.NewArgument("curve not supported")
	}
	if signature == nil || signature.R.Curve().Name() != curveName || signature.S.ScalarField().Curve().Name() != curveName || signature.R == nil || signature.S == nil || signature.R.IsAdditiveIdentity() || signature.S.IsZero() {
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

	e, err := v.variant.ComputeChallenge(suite, challengeR, challengePk, v.message)
	if err != nil {
		return errs.WrapFailed(err, "cannot create challenge scalar")
	}

	if signature.E != nil && !signature.E.Equal(e) {
		return errs.NewFailed("incompatible signature")
	}

	// 5. Let R = s⋅G - e⋅P.
	bigR := curve.ScalarBaseMult(signature.S).Sub(v.publicKey.A.ScalarMul(e))

	// 6. Fail if is_infinite(R).
	// 7. Fail if not has_even_y(R).
	// 8. Fail if x(R) ≠ r.
	if !signature.R.AffineX().Equal(bigR.AffineX()) || bigR.IsAdditiveIdentity() {
		return errs.NewVerification("signature is invalid")
	}
	if challengeR.Equal(signature.R) && !bigR.AffineY().IsEven() {
		return errs.NewVerification("signature is invalid")
	}

	return nil
}
