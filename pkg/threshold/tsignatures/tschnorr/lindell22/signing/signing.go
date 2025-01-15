package signing

import (
	"sort"

	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/eddsa"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/schnorr"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/schnorr/vanilla"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tschnorr"
)

func BigS(participants ds.Set[types.IdentityKey]) []byte {
	sortedIdentities := types.ByPublicKey(participants.List())
	sort.Sort(sortedIdentities)
	var bigS []byte
	for _, identity := range sortedIdentities {
		pid := identity.PublicKey().ToAffineCompressed()
		bigS = append(bigS, pid...)
	}

	return bigS
}

func Aggregate[V schnorr.Variant[V, M], M any](variant schnorr.Variant[V, M], protocol types.ThresholdSignatureProtocol, message M, partialPublicKeys *tsignatures.PartialPublicKeys, publicKey *schnorr.PublicKey, partialSignatures ds.Map[types.IdentityKey, *tschnorr.PartialSignature]) (signature *schnorr.Signature[V, M], err error) {
	sigs := partialSignatures.Values()
	sig0 := sigs[0]
	bigR := sig0.R.Curve().AdditiveIdentity()
	for _, sigI := range sigs {
		bigR = bigR.Add(sigI.R)
	}

	e, err := variant.ComputeChallenge(protocol.SigningSuite(), bigR, publicKey.A, message)
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

		sig := &schnorr.Signature[V, M]{
			Variant: variant,
			E:       partialSig.E,
			R:       partialSig.R,
			S:       partialSig.S,
		}
		verifier, err := variant.NewVerifierBuilder().
			WithSigningSuite(protocol.SigningSuite()).
			WithPublicKey(&schnorr.PublicKey{A: publicShareAdditive}).
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

	if eddsa.IsEd25519Compliant(protocol.SigningSuite()) {
		eddsaPublicKey := &eddsa.PublicKey{A: publicKey.A}
		eddsaSignature := &eddsa.Signature{
			Variant: vanilla.NewEdDsaCompatibleVariant(),
			E:       sig.E,
			R:       sig.R,
			S:       sig.S,
		}
		msg, ok := any(message).([]byte)
		if !ok {
			return nil, errs.NewVerification("unsupported message type")
		}
		if err := eddsa.Verify(eddsaPublicKey, msg, eddsaSignature); err != nil {
			return nil, errs.WrapVerification(err, "invalid partial signatures")
		}
	} else {
		verifier, err := variant.NewVerifierBuilder().
			WithSigningSuite(protocol.SigningSuite()).
			WithPublicKey(publicKey).
			WithMessage(message).
			Build()
		if err != nil {
			return nil, errs.WrapFailed(err, "could not build verifier")
		}
		if err := verifier.Verify(sig); err != nil {
			return nil, errs.WrapVerification(err, "invalid partial signatures")
		}
	}

	return sig, err
}

func aggregateInternal[V schnorr.Variant[V, M], M any](variant schnorr.Variant[V, M], partialSignatures ...*tschnorr.PartialSignature) (signature *schnorr.Signature[V, M], err error) {
	if len(partialSignatures) < 2 {
		return nil, errs.NewFailed("not enough partial signatures")
	}

	e := partialSignatures[0].E
	r := partialSignatures[0].R.Curve().AdditiveIdentity()
	s := partialSignatures[0].S.ScalarField().Zero()
	for _, partialSignature := range partialSignatures {
		if !e.Equal(partialSignature.E) {
			return nil, errs.NewFailed("invalid partial signature")
		}

		// step 1: r <- Σ ri
		r = r.Add(partialSignature.R)

		// step 2: s <- Σ si
		s = s.Add(partialSignature.S)
	}

	return &schnorr.Signature[V, M]{
		Variant: variant,
		E:       e,
		R:       r,
		S:       s,
	}, nil
}
