package noninteractive_signing

import (
	"io"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves/curveutils"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/schnorr"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/schnorr/vanilla"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts"
)

type Cosigner[V schnorr.Variant[V, M], M any] struct {
	// Base participant
	myAuthKey  types.AuthKey
	Prng       io.Reader
	Protocol   types.ThresholdSignatureProtocol
	Round      int
	Transcript transcripts.Transcript

	// Threshold participant
	mySharingId   types.SharingID
	sharingConfig types.SharingConfig

	myShard *lindell22.Shard
	ppm     *lindell22.PreProcessingMaterial
	quorum  ds.Set[types.IdentityKey]

	variant schnorr.Variant[V, M]

	_ ds.Incomparable
}

var _ types.ThresholdSignatureParticipant = (*Cosigner[vanilla.EdDsaCompatibleVariant, []byte])(nil)

func (c *Cosigner[V, M]) IdentityKey() types.IdentityKey {
	return c.myAuthKey
}

func (c *Cosigner[V, M]) SharingId() types.SharingID {
	return c.mySharingId
}

func (c *Cosigner[V, M]) Quorum() ds.Set[types.IdentityKey] {
	return c.quorum
}

func NewCosigner[V schnorr.Variant[V, M], M any](myAuthKey types.AuthKey, myShard *lindell22.Shard, protocol types.ThresholdSignatureProtocol, quorum ds.Set[types.IdentityKey], ppm *lindell22.PreProcessingMaterial, variant schnorr.Variant[V, M], transcript transcripts.Transcript, prng io.Reader) (cosigner *Cosigner[V, M], err error) {
	if err := validateCosignerInputs(myAuthKey, myShard, protocol, quorum, ppm, prng); err != nil {
		return nil, errs.WrapArgument(err, "invalid arguments")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.Reverse().Get(myAuthKey)
	if !exists {
		return nil, errs.NewMissing("could not find my sharing id")
	}

	cosigner = &Cosigner[V, M]{
		myAuthKey:     myAuthKey,
		Prng:          prng,
		Protocol:      protocol,
		Round:         1,
		Transcript:    transcript,
		mySharingId:   mySharingId,
		sharingConfig: sharingConfig,
		myShard:       myShard,
		quorum:        quorum,
		variant:       variant,
		ppm:           ppm,
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
	if quorum.Size() > 0 && !curveutils.AllIdentityKeysWithSameCurve(quorum.List()[0].PublicKey().Curve(), quorum.List()...) {
		return errs.NewCurve("participants have different curves")
	}
	return nil
}
