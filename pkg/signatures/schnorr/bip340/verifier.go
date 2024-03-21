package bip340

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
)

type verifierBuilder struct {
	publicKey          *schnorr.PublicKey
	message            []byte
	nonceCommitment    curves.Point
	challengePublicKey curves.Point
}

type verifier struct {
	publicKey          *schnorr.PublicKey
	message            []byte
	nonceCommitment    curves.Point
	challengePublicKey curves.Point
}

var _ schnorr.VerifierBuilder[TaprootVariant] = (*verifierBuilder)(nil)
var _ schnorr.Verifier[TaprootVariant] = (*verifier)(nil)

func (v *verifierBuilder) WithSignatureProtocol(_ types.SignatureProtocol) schnorr.VerifierBuilder[TaprootVariant] {
	return v
}

func (v *verifierBuilder) WithPublicKey(publicKey *schnorr.PublicKey) schnorr.VerifierBuilder[TaprootVariant] {
	v.publicKey = publicKey
	return v
}

func (v *verifierBuilder) WithMessage(message []byte) schnorr.VerifierBuilder[TaprootVariant] {
	v.message = message
	return v
}

func (v *verifierBuilder) WithChallengeCommitment(partialNonceCommitment curves.Point) schnorr.VerifierBuilder[TaprootVariant] {
	v.nonceCommitment = partialNonceCommitment
	return v
}

func (v *verifierBuilder) WithChallengePublicKey(challengePublicKey curves.Point) schnorr.VerifierBuilder[TaprootVariant] {
	v.challengePublicKey = challengePublicKey
	return v
}

func (v *verifierBuilder) Build() schnorr.Verifier[TaprootVariant] {
	return &verifier{
		publicKey:          v.publicKey,
		message:            v.message,
		nonceCommitment:    v.nonceCommitment,
		challengePublicKey: v.challengePublicKey,
	}
}

func (v *verifier) Verify(signature *schnorr.Signature[TaprootVariant]) error {
	if v.publicKey == nil || v.publicKey.A == nil || v.publicKey.A.Curve().Name() != suite.Curve().Name() {
		return errs.NewArgument("curve not supported")
	}
	if signature == nil || signature.R.Curve().Name() != suite.Curve().Name() || signature.S.ScalarField().Curve().Name() != suite.Curve().Name() || signature.R == nil || signature.S == nil || signature.R.IsIdentity() || signature.S.IsZero() {
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
	eBytes := taprootVariant.ComputeChallengeBytes(challengeR, challengePk, v.message)
	e, err := schnorr.MakeGenericSchnorrChallenge(suite, eBytes)
	if err != nil {
		return errs.WrapVerification(err, "invalid signature")
	}

	if signature.E != nil && !signature.E.Equal(e) {
		return errs.NewFailed("incompatible signature")
	}

	// 5. Let R = s⋅G - e⋅P.
	bigR := suite.Curve().ScalarBaseMult(signature.S).Sub(bigP.Mul(e))

	// 6. Fail if is_infinite(R).
	// 7. Fail if not has_even_y(R).
	// 8. Fail if x(R) ≠ r.
	if !signature.R.AffineX().Equal(bigR.AffineX()) || bigR.IsIdentity() {
		return errs.NewVerification("signature is invalid")
	}
	if challengeR.Equal(signature.R) && !bigR.AffineY().IsEven() {
		return errs.NewVerification("signature is invalid")
	}

	return nil
}
