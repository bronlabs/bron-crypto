package signing

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"sort"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	//"github.com/bronlabs/bron-crypto/pkg/signatures/eddsa"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr"
)

func BigS(participants ds.Set[types.IdentityKey]) []byte {
	sortedIdentities := types.ByPublicKey(participants.List())
	sort.Sort(sortedIdentities)
	var bigS []byte
	for _, identity := range sortedIdentities {
		pid := identity.PublicKeyBytes()
		bigS = append(bigS, pid...)
	}

	return bigS
}

func Aggregate[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S], V schnorr.Variant[V, M, P, F, S], M any](variant schnorr.Variant[V, M, P, F, S], protocol types.ThresholdSignatureProtocol[C, P, F, S], message M, partialPublicKeys *tsignatures.PartialPublicKeys[C, P, F, S], publicKey *schnorr.PublicKey[P, F, S], partialSignatures ds.Map[types.IdentityKey, *tschnorr.PartialSignature[P, F, S]]) (signature *schnorr.Signature[V, M, P, F, S], err error) {
	sigs := partialSignatures.Values()
	sig0 := sigs[0]

	curve, err := curves.GetCurve(sig0.R)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not get curve")
	}

	bigR := curve.OpIdentity()
	for _, sigI := range sigs {
		bigR = bigR.Op(sigI.R)
	}

	e, err := variant.ComputeChallenge(protocol.SigningSuite().Hash(), bigR, publicKey.A, message)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot compute challenge")
	}
	for _, sigI := range sigs {
		if !sigI.E.Equal(sig0.E) || !sigI.E.Equal(e) {
			return nil, errs.NewVerification("invalid partial signatures")
		}
	}

	signers := hashset.NewComparableHashSet(partialSignatures.Keys()...)
	additivePartialPublicKeys, err := partialPublicKeys.ToAdditive(protocol, signers)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert partial public keys to additive")
	}

	for _, identity := range partialSignatures.Keys() {
		partialSig, exists := partialSignatures.Get(identity)
		if !exists {
			return nil, errs.NewVerification("invalid partial signatures")
		}

		publicShareAdditive, exists := additivePartialPublicKeys.Get(identity)
		if !exists {
			return nil, errs.NewVerification("invalid partial signatures")
		}

		sig := &schnorr.Signature[V, M, P, F, S]{
			Variant: variant,
			E:       partialSig.E,
			R:       partialSig.R,
			S:       partialSig.S,
		}
		verifier, err := variant.NewVerifierBuilder().
			WithHashFunc(protocol.SigningSuite().Hash()).
			WithPublicKey(&schnorr.PublicKey[P, F, S]{A: publicShareAdditive}).
			WithMessage(message).
			WithChallengeCommitment(bigR).
			WithChallengePublicKey(publicKey.A).
			Build()
		if err != nil {
			return nil, errs.WrapFailed(err, "could not build verifier")
		}
		if err := verifier.Verify(sig); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, identity.String(), "invalid partial signatures")
		}
	}

	sig, err := aggregateInternal(variant, partialSignatures.Values()...)
	if err != nil {
		return nil, errs.WrapVerification(err, "invalid partial signatures")
	}

	//if eddsa.IsEd25519Compliant(protocol.SigningSuite()) {
	//	eddsaPublicKey := &eddsa.PublicKey{A: publicKey.A}
	//	eddsaSignature := &eddsa.Signature{
	//		Variant: vanilla.NewEdDsaCompatibleVariant(),
	//		E:       sig.E,
	//		R:       sig.R,
	//		S:       sig.S,
	//	}
	//	msg, ok := any(message).([]byte)
	//	if !ok {
	//		return nil, errs.NewVerification("unsupported message type")
	//	}
	//	if err := eddsa.Verify(eddsaPublicKey, msg, eddsaSignature); err != nil {
	//		return nil, errs.WrapVerification(err, "invalid partial signatures")
	//	}
	//} else {
	verifier, err := variant.NewVerifierBuilder().
		WithHashFunc(protocol.SigningSuite().Hash()).
		WithPublicKey(publicKey).
		WithMessage(message).
		Build()
	if err != nil {
		return nil, errs.WrapFailed(err, "could not build verifier")
	}
	if err := verifier.Verify(sig); err != nil {
		return nil, errs.WrapVerification(err, "invalid partial signatures")
	}
	//}

	return sig, err
}

func aggregateInternal[P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S], V schnorr.Variant[V, M, P, F, S], M any](variant schnorr.Variant[V, M, P, F, S], partialSignatures ...*tschnorr.PartialSignature[P, F, S]) (signature *schnorr.Signature[V, M, P, F, S], err error) {
	if len(partialSignatures) < 2 {
		return nil, errs.NewFailed("not enough partial signatures")
	}

	curve, err := curves.GetCurve(partialSignatures[0].R)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not get curve")
	}

	e := partialSignatures[0].E
	r := curve.OpIdentity()
	s := curve.ScalarField().Zero()
	for _, partialSignature := range partialSignatures {
		if !e.Equal(partialSignature.E) {
			return nil, errs.NewFailed("invalid partial signature")
		}

		// step 1: r <- Σ ri
		r = r.Op(partialSignature.R)

		// step 2: s <- Σ si
		s = s.Add(partialSignature.S)
	}

	return &schnorr.Signature[V, M, P, F, S]{
		Variant: variant,
		E:       e,
		R:       r,
		S:       s,
	}, nil
}
