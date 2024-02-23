package noninteractive_signing

import (
	"fmt"
	"io"

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
	przsSampleParticipant *sample.Participant

	myAuthKey   types.AuthKey
	mySharingId types.SharingID
	myShard     *lindell22.Shard
	ppm         *lindell22.PreProcessingMaterial
	cosigners   ds.Set[types.IdentityKey]

	variant       schnorr.Variant[F]
	sharingConfig types.SharingConfig
	protocol      types.ThresholdSignatureProtocol
	prng          io.Reader

	_ ds.Incomparable
}

var _ types.ThresholdSignatureParticipant = (*Cosigner[schnorr.EdDsaCompatibleVariant])(nil)

func (c *Cosigner[F]) IdentityKey() types.IdentityKey {
	return c.myAuthKey
}

func (c *Cosigner[F]) SharingId() types.SharingID {
	return c.mySharingId
}

func NewCosigner[F schnorr.Variant[F]](sessionId []byte, myAuthKey types.AuthKey, myShard *lindell22.Shard, protocol types.ThresholdSignatureProtocol, cosigners ds.Set[types.IdentityKey], ppm *lindell22.PreProcessingMaterial, variant schnorr.Variant[F], transcript transcripts.Transcript, prng io.Reader) (cosigner *Cosigner[F], err error) {
	if err := validateCosignerInputs(sessionId, myAuthKey, myShard, protocol, cosigners, ppm, prng); err != nil {
		return nil, errs.WrapArgument(err, "invalid arguments")
	}

	dst := fmt.Sprintf("%s-%s", transcriptLabel, protocol.Curve().Name())
	_, sessionId, err = hagrid.InitialiseProtocol(transcript, sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	przsPrngFactory, err := chacha.NewChachaPRNG(nil, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create PRNG factory")
	}
	przsParticipant, err := sample.NewParticipant(sessionId, myAuthKey, ppm.PrivateMaterial.Seeds, protocol, cosigners, przsPrngFactory)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create PRZS sampler")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.Reverse().Get(myAuthKey)
	if !exists {
		return nil, errs.NewMissing("could not find my sharing id")
	}

	cosigner = &Cosigner[F]{
		przsSampleParticipant: przsParticipant,
		myAuthKey:             myAuthKey,
		myShard:               myShard,
		cosigners:             cosigners,
		variant:               variant,
		protocol:              protocol,
		prng:                  prng,
		mySharingId:           mySharingId,
		sharingConfig:         sharingConfig,
		ppm:                   ppm,
	}

	if err := types.ValidateThresholdSignatureProtocol(cosigner, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct cnoninteractive cosigner")
	}

	return cosigner, nil
}

func validateCosignerInputs(sessionId []byte, authKey types.AuthKey, shard *lindell22.Shard, protocol types.ThresholdSignatureProtocol, cosigners ds.Set[types.IdentityKey], ppm *lindell22.PreProcessingMaterial, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewIsNil("session id is empty")
	}
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
	if !cosigners.IsSubSet(ppm.PreSigners) {
		return errs.NewValidation("cosigners not a subset of pre-signers")
	}
	if !cosigners.Contains(authKey) {
		return errs.NewFailed("not a member of cosigners")
	}
	return nil
}
