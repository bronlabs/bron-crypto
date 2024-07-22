package zilliqa

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

var _ schnorr.VerifierBuilder[ZilliqaVariant, []byte] = (*verifierBuilder)(nil)
var _ schnorr.Verifier[ZilliqaVariant, []byte] = (*verifier)(nil)

func (v *verifierBuilder) WithSigningSuite(_ types.SigningSuite) schnorr.VerifierBuilder[ZilliqaVariant, []byte] {
	return v
}

func (v *verifierBuilder) WithPublicKey(publicKey *schnorr.PublicKey) schnorr.VerifierBuilder[ZilliqaVariant, []byte] {
	v.publicKey = publicKey
	return v
}

func (v *verifierBuilder) WithMessage(message []byte) schnorr.VerifierBuilder[ZilliqaVariant, []byte] {
	v.message = message
	return v
}

func (v *verifierBuilder) WithChallengeCommitment(partialNonceCommitment curves.Point) schnorr.VerifierBuilder[ZilliqaVariant, []byte] {
	v.nonceCommitment = partialNonceCommitment
	return v
}

func (v *verifierBuilder) WithChallengePublicKey(challengePublicKey curves.Point) schnorr.VerifierBuilder[ZilliqaVariant, []byte] {
	v.challengePublicKey = challengePublicKey
	return v
}

func (v *verifierBuilder) Build() (schnorr.Verifier[ZilliqaVariant, []byte], error) {
	return &verifier{
		publicKey:          v.publicKey,
		message:            v.message,
		nonceCommitment:    v.nonceCommitment,
		challengePublicKey: v.challengePublicKey,
	}, nil
}

func (v *verifier) Verify(signature *schnorr.Signature[ZilliqaVariant, []byte]) error {
	if v.publicKey == nil || signature == nil || len(v.message) == 0 {
		return errs.NewIsNil("argument is empty")
	}

	if v.publicKey.A == nil || v.publicKey.A.Curve().Name() != curveName {
		return errs.NewFailed("incompatible public key")
	}

	if !v.publicKey.A.IsInPrimeSubGroup() {
		return errs.NewValidation("Public Key not in the prime subgroup")
	}

	if signature.E == nil || signature.E.ScalarField().Curve().Name() != curveName || signature.S == nil || signature.S.ScalarField().Curve().Name() != curveName {
		return errs.NewFailed("incompatible signature")
	}

	if signature.E.IsZero() || signature.S.IsZero() {
		return errs.NewVerification("invalid E or S value, cannot be zero")
	}

	l := v.publicKey.A.ScalarMul(signature.E)
	r := curve.ScalarBaseMult(signature.S)
	q := r.Add(l)

	if signature.R != nil && !signature.R.Equal(q) {
		return errs.NewFailed("incompatible signature")
	}

	protocol, err := types.NewSigningSuite(curve, hashFunc)
	if err != nil {
		return errs.WrapFailed(err, "cannot create protocol")
	}

	challengePk := v.challengePublicKey
	if challengePk == nil {
		challengePk = v.publicKey.A
	}
	challengeR := v.nonceCommitment
	if challengeR == nil {
		challengeR = signature.R
	}
	eCheck, err := zilliqaVariant.ComputeChallenge(protocol, challengeR, challengePk, v.message)
	if err != nil {
		return errs.WrapFailed(err, "cannot compute challenge")
	}

	if !signature.E.Equal(eCheck) {
		return errs.NewVerification("invalid signature")
	}

	return nil
}
