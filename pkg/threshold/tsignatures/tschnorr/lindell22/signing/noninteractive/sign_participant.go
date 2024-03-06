package noninteractive_signing

import (
	"fmt"
	"io"
	"sort"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/chacha"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/sample"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

type Cosigner[F schnorr.Variant[F]] struct {
	*types.BaseParticipant[types.ThresholdSignatureProtocol]

	przsSampleParticipant *sample.Participant

	myAuthKey   types.AuthKey
	mySharingId types.SharingID
	myShard     *lindell22.Shard
	ppm         *lindell22.PreProcessingMaterial
	quorum      ds.Set[types.IdentityKey]

	variant       schnorr.Variant[F]
	sharingConfig types.SharingConfig

	_ ds.Incomparable
}

var _ types.ThresholdSignatureParticipant = (*Cosigner[schnorr.EdDsaCompatibleVariant])(nil)

func (c *Cosigner[F]) IdentityKey() types.IdentityKey {
	return c.myAuthKey
}

func (c *Cosigner[F]) SharingId() types.SharingID {
	return c.mySharingId
}

func NewCosigner[F schnorr.Variant[F]](myAuthKey types.AuthKey, myShard *lindell22.Shard, protocol types.ThresholdSignatureProtocol, quorum ds.Set[types.IdentityKey], ppm *lindell22.PreProcessingMaterial, variant schnorr.Variant[F], transcript transcripts.Transcript, prng io.Reader) (cosigner *Cosigner[F], err error) {
	if err := validateCosignerInputs(myAuthKey, myShard, protocol, quorum, ppm, prng); err != nil {
		return nil, errs.WrapArgument(err, "invalid arguments")
	}

	// In zero share sampling, the sampler uses its session id to salt the seeds and produce the shares. This requires the session id
	// to be random as well as unique, which will be the case if participants use agreeonrandom primitive.
	// As shared randomness via agreeonrandom requires interactivity, and since this cosigner is noninteractive, instead we salt
	// the seeds with the hash of public signature material which should have high enough entropy.
	// This is secure if used only once, which should be the case as the user of this primitive should already ensure presignatures are
	// not used more than once.
	// We call this non-interactive session id based on how sampler uses it, even though this is not really a session id!
	nonInteractiveSessionId, err := produceSharedOneTimeUseRandomValue(myAuthKey, protocol, quorum, ppm)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce non interactive session id")
	}

	dst := fmt.Sprintf("%s-%s", transcriptLabel, protocol.Curve().Name())
	_, sessionId, err := hagrid.InitialiseProtocol(transcript, nonInteractiveSessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	przsPrngFactory, err := chacha.NewChachaPRNG(nil, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create PRNG factory")
	}
	przsParticipant, err := sample.NewParticipant(sessionId, myAuthKey, ppm.PrivateMaterial.Seeds, protocol, quorum, przsPrngFactory)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create PRZS sampler")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.Reverse().Get(myAuthKey)
	if !exists {
		return nil, errs.NewMissing("could not find my sharing id")
	}

	cosigner = &Cosigner[F]{
		BaseParticipant:       types.NewBaseParticipant(prng, protocol, 1, sessionId, transcript),
		przsSampleParticipant: przsParticipant,
		myAuthKey:             myAuthKey,
		myShard:               myShard,
		quorum:                quorum,
		variant:               variant,
		mySharingId:           mySharingId,
		sharingConfig:         sharingConfig,
		ppm:                   ppm,
	}

	if err := types.ValidateThresholdSignatureProtocol(cosigner, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct non-interactive cosigner")
	}

	return cosigner, nil
}

func validateCosignerInputs(authKey types.AuthKey, shard *lindell22.Shard, protocol types.ThresholdSignatureProtocol, quorum ds.Set[types.IdentityKey], ppm *lindell22.PreProcessingMaterial, prng io.Reader) error {
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config")
	}
	if err := shard.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "shard")
	}
	if err := ppm.Validate(authKey, protocol); err != nil {
		return errs.WrapValidation(err, "preprocessing material")
	}
	if prng == nil {
		return errs.NewIsNil("prng")
	}
	if !quorum.IsSubSet(ppm.PreSigners) {
		return errs.NewValidation("quorum not a subset of pre-signers")
	}
	if !quorum.Contains(authKey) {
		return errs.NewFailed("not a member of quorum")
	}
	return nil
}

func produceSharedOneTimeUseRandomValue(myIdentityKey types.IdentityKey, protocol types.ThresholdSignatureProtocol, quorum ds.Set[types.IdentityKey], ppm *lindell22.PreProcessingMaterial) ([]byte, error) {
	ro := base.RandomOracleHashFunction()
	sortedQuorum := quorum.List()
	sort.Sort(types.ByPublicKey(sortedQuorum))
	for _, identity := range sortedQuorum {
		if identity.Equal(myIdentityKey) {
			if _, err := ro.Write(protocol.Curve().ScalarBaseMult(ppm.PrivateMaterial.K1).ToAffineCompressed()); err != nil {
				return nil, errs.WrapHashing(err, "could not write k1*G to RO hasher")
			}
			if _, err := ro.Write(protocol.Curve().ScalarBaseMult(ppm.PrivateMaterial.K2).ToAffineCompressed()); err != nil {
				return nil, errs.WrapHashing(err, "could not write k2*G to RO hasher")
			}
		} else {
			R1, exists := ppm.PreSignature.BigR1.Get(identity)
			if !exists {
				return nil, errs.NewMissing("could not find R1 from %s", identity.String())
			}
			if _, err := ro.Write(R1.ToAffineCompressed()); err != nil {
				return nil, errs.WrapHashing(err, "could not write R1 from %s", identity.String())
			}
			R2, exists := ppm.PreSignature.BigR2.Get(identity)
			if !exists {
				return nil, errs.NewMissing("could not find R2 from %s", identity.String())
			}
			if _, err := ro.Write(R2.ToAffineCompressed()); err != nil {
				return nil, errs.WrapHashing(err, "could not write R2 from %s", identity.String())
			}
		}
	}
	return ro.Sum(nil), nil
}
