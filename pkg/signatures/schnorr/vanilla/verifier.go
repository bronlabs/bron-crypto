package vanilla

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr"
	"hash"
	"reflect"
)

type verifierBuilder[P curves.Point[P, B, S], B fields.FiniteFieldElement[B], S fields.PrimeFieldElement[S]] struct {
	hashFunc           func() hash.Hash
	publicKey          *schnorr.PublicKey[P, B, S]
	message            []byte
	nonceCommitment    P
	challengePublicKey P
}

type verifier[P curves.Point[P, B, S], B fields.FiniteFieldElement[B], S fields.PrimeFieldElement[S]] struct {
	hashFunc           func() hash.Hash
	publicKey          *schnorr.PublicKey[P, B, S]
	message            []byte
	nonceCommitment    P
	challengePublicKey P
}

func (v *verifierBuilder[P, B, S]) WithHashFunc(hashFunc func() hash.Hash) schnorr.VerifierBuilder[EdDsaCompatibleVariant[P, B, S], []byte, P, B, S] {
	v.hashFunc = hashFunc
	return v
}

func (v *verifierBuilder[P, B, S]) WithPublicKey(publicKey *schnorr.PublicKey[P, B, S]) schnorr.VerifierBuilder[EdDsaCompatibleVariant[P, B, S], []byte, P, B, S] {
	v.publicKey = publicKey
	return v
}

func (v *verifierBuilder[P, B, S]) WithMessage(message []byte) schnorr.VerifierBuilder[EdDsaCompatibleVariant[P, B, S], []byte, P, B, S] {
	v.message = message
	return v
}

func (v *verifierBuilder[P, B, S]) WithChallengeCommitment(partialNonceCommitment P) schnorr.VerifierBuilder[EdDsaCompatibleVariant[P, B, S], []byte, P, B, S] {
	v.nonceCommitment = partialNonceCommitment
	return v
}

func (v *verifierBuilder[P, B, S]) WithChallengePublicKey(challengePublicKey P) schnorr.VerifierBuilder[EdDsaCompatibleVariant[P, B, S], []byte, P, B, S] {
	v.challengePublicKey = challengePublicKey
	return v
}

func (v *verifierBuilder[P, B, S]) Build() (schnorr.Verifier[EdDsaCompatibleVariant[P, B, S], []byte, P, B, S], error) {
	return &verifier[P, B, S]{
		hashFunc:           v.hashFunc,
		publicKey:          v.publicKey,
		message:            v.message,
		nonceCommitment:    v.nonceCommitment,
		challengePublicKey: v.challengePublicKey,
	}, nil
}

func (v *verifier[P, B, S]) Verify(signature *schnorr.Signature[EdDsaCompatibleVariant[P, B, S], []byte, P, B, S]) error {
	//if err := types.ValidateSigningSuite(v.suite); err != nil {
	//	return errs.WrapArgument(err, "invalid cipher suite")
	//}
	//if v.publicKey == nil || v.publicKey.A == nil || v.publicKey.A.IsAdditiveIdentity() || v.publicKey.A.CurveTrait().Name() != v.suite.CurveTrait().Name() {
	//	return errs.NewArgument("invalid signature")
	//}
	//if signature == nil || signature.R == nil || signature.R.CurveTrait().Name() != v.suite.CurveTrait().Name() ||
	//	signature.S == nil || signature.S.ScalarField().CurveTrait().Name() != v.suite.CurveTrait().Name() {
	//
	//	return errs.NewArgument("invalid signature")
	//}
	//
	//// this check is not part of the ed25519 standard yet if the public key is of small order then the signature will be susceptible
	//// to a key substitution attack (specifically, it won't be bound to a public key (SBS) and a signature cannot be bound to a unique message in presence of malicious keys (MBS)).
	//// Refer to section 5.4 of https://eprint.iacr.org/2020/823.pdf and https://eprint.iacr.org/2020/1244.pdf
	//if !v.publicKey.A.IsInPrimeSubGroup() {
	//	return errs.NewValidation("Public Key not in the prime subgroup")
	//}
	challengeR := v.nonceCommitment
	if reflect.ValueOf(challengeR).IsNil() { // TODO(aalireza): any idea how to work this around? (challenge.(PointTrait[R,..]) == nil does not work neither)
		challengeR = signature.R
	}
	challengePk := v.challengePublicKey
	if reflect.ValueOf(challengePk).IsNil() {
		challengePk = v.publicKey.A
	}
	curve, err := curves.GetCurve(signature.R)
	if err != nil {
		return errs.WrapFailed(err, "cannot get curve")
	}

	variant := NewEdDsaCompatibleVariant[P]()
	e, err := variant.ComputeChallenge(v.hashFunc, challengeR, challengePk, v.message)
	if err != nil {
		return errs.WrapFailed(err, "cannot create challenge scalar")
	}
	if fields.PrimeFieldElement[S](signature.E) != nil && !signature.E.Equal(e) {
		return errs.NewFailed("incompatible schnorr signature")
	}

	// TODO(aalireza): what to do with cofactor?
	//cofactorNat := v.suite.CurveTrait().CoFactor()
	//cofactor := v.suite.CurveTrait().ScalarField().Element().SetNat(cofactorNat)
	left := curve.Generator().ScalarMul(signature.S)
	right := signature.R.Op(v.publicKey.A.ScalarMul(e))
	if !left.Equal(right) {
		return errs.NewVerification("invalid signature")
	}

	return nil
}
