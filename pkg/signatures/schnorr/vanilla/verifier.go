package vanilla

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr"
)

type verifierBuilder struct {
	suite              types.SigningSuite
	publicKey          *schnorr.PublicKey
	message            []byte
	nonceCommitment    curves.Point
	challengePublicKey curves.Point
}

type verifier struct {
	suite              types.SigningSuite
	publicKey          *schnorr.PublicKey
	message            []byte
	nonceCommitment    curves.Point
	challengePublicKey curves.Point
}

var _ schnorr.VerifierBuilder[EdDsaCompatibleVariant, []byte] = (*verifierBuilder)(nil)
var _ schnorr.Verifier[EdDsaCompatibleVariant, []byte] = (*verifier)(nil)

func (v *verifierBuilder) WithSigningSuite(suite types.SigningSuite) schnorr.VerifierBuilder[EdDsaCompatibleVariant, []byte] {
	v.suite = suite
	return v
}

func (v *verifierBuilder) WithPublicKey(publicKey *schnorr.PublicKey) schnorr.VerifierBuilder[EdDsaCompatibleVariant, []byte] {
	v.publicKey = publicKey
	return v
}

func (v *verifierBuilder) WithMessage(message []byte) schnorr.VerifierBuilder[EdDsaCompatibleVariant, []byte] {
	v.message = message
	return v
}

func (v *verifierBuilder) WithChallengeCommitment(partialNonceCommitment curves.Point) schnorr.VerifierBuilder[EdDsaCompatibleVariant, []byte] {
	v.nonceCommitment = partialNonceCommitment
	return v
}

func (v *verifierBuilder) WithChallengePublicKey(challengePublicKey curves.Point) schnorr.VerifierBuilder[EdDsaCompatibleVariant, []byte] {
	v.challengePublicKey = challengePublicKey
	return v
}

func (v *verifierBuilder) Build() (schnorr.Verifier[EdDsaCompatibleVariant, []byte], error) {
	return &verifier{
		suite:              v.suite,
		publicKey:          v.publicKey,
		message:            v.message,
		nonceCommitment:    v.nonceCommitment,
		challengePublicKey: v.challengePublicKey,
	}, nil
}

func (v *verifier) Verify(signature *schnorr.Signature[EdDsaCompatibleVariant, []byte]) error {
	if err := types.ValidateSigningSuite(v.suite); err != nil {
		return errs.WrapArgument(err, "invalid cipher suite")
	}
	if v.publicKey == nil || v.publicKey.A == nil || v.publicKey.A.IsAdditiveIdentity() || v.publicKey.A.Curve().Name() != v.suite.Curve().Name() {
		return errs.NewArgument("invalid signature")
	}
	if signature == nil || signature.R == nil || signature.R.Curve().Name() != v.suite.Curve().Name() ||
		signature.S == nil || signature.S.ScalarField().Curve().Name() != v.suite.Curve().Name() {

		return errs.NewArgument("invalid signature")
	}

	// this check is not part of the ed25519 standard yet if the public key is of small order then the signature will be susceptible
	// to a key substitution attack (specifically, it won't be bound to a public key (SBS) and a signature cannot be bound to a unique message in presence of malicious keys (MBS)).
	// Refer to section 5.4 of https://eprint.iacr.org/2020/823.pdf and https://eprint.iacr.org/2020/1244.pdf
	if !v.publicKey.A.IsInPrimeSubGroup() {
		return errs.NewValidation("Public Key not in the prime subgroup")
	}
	challengeR := v.nonceCommitment
	if challengeR == nil {
		challengeR = signature.R
	}
	challengePk := v.challengePublicKey
	if challengePk == nil {
		challengePk = v.publicKey.A
	}
	e, err := edDsaCompatibleVariant.ComputeChallenge(v.suite, challengeR, challengePk, v.message)
	if err != nil {
		return errs.WrapFailed(err, "cannot create challenge scalar")
	}
	if signature.E != nil && !signature.E.Equal(e) {
		return errs.NewFailed("incompatible schnorr signature")
	}

	cofactorNat := v.suite.Curve().CoFactor()
	cofactor := v.suite.Curve().ScalarField().Element().SetNat(cofactorNat)
	left := v.suite.Curve().ScalarBaseMult(signature.S.Mul(cofactor))
	right := signature.R.ScalarMul(cofactor).Add(v.publicKey.A.ScalarMul(e.Mul(cofactor)))
	if !left.Equal(right) {
		return errs.NewVerification("invalid signature")
	}

	return nil
}
