package signing

import (
	"sort"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr"
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

func Aggregate[V schnorr.Variant[V]](variant schnorr.Variant[V], protocol types.ThresholdSignatureProtocol, message []byte, publicShares ds.Map[types.IdentityKey, *tsignatures.PartialPublicKeys], publicKey *schnorr.PublicKey, partialSignatures ds.Map[types.IdentityKey, *tschnorr.PartialSignature]) (signature *schnorr.Signature[V], err error) {
	sigs := partialSignatures.Values()
	sig0 := sigs[0]
	r := sig0.R.Curve().Identity()
	for _, sigI := range sigs {
		r = r.Add(sigI.R)
	}

	eBytes := variant.ComputeChallengeBytes(r, publicKey.A, message)
	e, err := schnorr.MakeGenericSchnorrChallenge(protocol.SigningSuite(), eBytes)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "cannot compute challenge")
	}
	for _, sigI := range sigs {
		if !sigI.E.Equal(sig0.E) || !sigI.E.Equal(e) {
			return nil, errs.NewVerification("invalid partial signatures")
		}
	}

	signers := partialSignatures.Keys()
	for _, identity := range partialSignatures.Keys() {
		partialSig, exists := partialSignatures.Get(identity)
		if !exists {
			return nil, errs.NewVerification("invalid partial signatures")
		}

		partialPublicKeyShares, exists := publicShares.Get(identity)
		if !exists {
			return nil, errs.NewVerification("invalid partial signatures")
		}

		partialPublicKeys, err := partialPublicKeyShares.ToAdditive(protocol, signers)
		if err != nil {
			return nil, errs.WrapVerification(err, "invalid partial signatures")
		}

		publicShareAdditive, exists := partialPublicKeys.Get(identity)
		if !exists {
			return nil, errs.NewVerification("invalid partial signatures")
		}

		sig := &schnorr.Signature[V]{
			Variant: variant,
			E:       partialSig.E,
			R:       partialSig.R,
			S:       partialSig.S,
		}
		verifier := variant.NewVerifierBuilder().
			WithSignatureProtocol(protocol.SigningSuite()).
			WithPublicKey(&schnorr.PublicKey{A: publicShareAdditive}).
			WithMessage(message).
			WithChallengeCommitment(r).
			WithChallengePublicKey(publicKey.A).
			Build()
		err = verifier.Verify(sig)
		if err != nil {
			return nil, errs.WrapIdentifiableAbort(err, identity.PublicKey().ToAffineCompressed(), "invalid partial signatures")
		}
	}

	sig, err := aggregateInternal(variant, partialSignatures.Values()...)
	if err != nil {
		return nil, errs.WrapVerification(err, "invalid partial signatures")
	}

	verifier := variant.NewVerifierBuilder().
		WithSignatureProtocol(protocol.SigningSuite()).
		WithPublicKey(publicKey).
		WithMessage(message).
		Build()
	if err := verifier.Verify(sig); err != nil {
		return nil, errs.WrapVerification(err, "invalid partial signatures")
	}

	return sig, err
}

func aggregateInternal[V schnorr.Variant[V]](variant schnorr.Variant[V], partialSignatures ...*tschnorr.PartialSignature) (signature *schnorr.Signature[V], err error) {
	if len(partialSignatures) < 2 {
		return nil, errs.NewFailed("not enough partial signatures")
	}

	e := partialSignatures[0].E
	r := partialSignatures[0].R.Curve().Identity()
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

	return &schnorr.Signature[V]{
		Variant: variant,
		E:       e,
		R:       r,
		S:       s,
	}, nil
}
