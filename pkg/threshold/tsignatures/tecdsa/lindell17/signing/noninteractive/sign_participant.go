package noninteractive_signing

import (
	"io"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
)

var _ types.ThresholdSignatureParticipant = (*Cosigner)(nil)

type Cosigner struct {
	myAuthKey             types.AuthKey
	mySharingId           types.SharingID
	myShard               *lindell17.Shard
	preProcessingMaterial *lindell17.PreProcessingMaterial

	initiatorIdentity   types.IdentityKey
	aggregatorIdentity  types.IdentityKey
	aggregatorSharingId types.SharingID

	protocol types.ThresholdSignatureProtocol
	prng     io.Reader

	_ ds.Incomparable
}

func (p *Cosigner) IdentityKey() types.IdentityKey {
	return p.myAuthKey
}

func (p *Cosigner) AuthKey() types.AuthKey {
	return p.myAuthKey
}

func (p *Cosigner) SharingId() types.SharingID {
	return p.mySharingId
}

func (p *Cosigner) IsSignatureAggregator() bool {
	return p.aggregatorIdentity.Equal(p.IdentityKey())
}

func (p *Cosigner) Quorum() ds.Set[types.IdentityKey] {
	return hashset.NewHashableHashSet(p.initiatorIdentity, p.aggregatorIdentity)
}

func NewCosigner(protocol types.ThresholdSignatureProtocol, myAuthKey types.AuthKey, myShard *lindell17.Shard, ppm *lindell17.PreProcessingMaterial, initiatorIdentity, aggregatorIdentity types.IdentityKey, prng io.Reader) (participant *Cosigner, err error) {
	if err := validateCosignerInputs(protocol, myAuthKey, myShard, ppm, initiatorIdentity, aggregatorIdentity, prng); err != nil {
		return nil, errs.WrapFailed(err, "failed to validate inputs")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.Reverse().Get(myAuthKey)
	if !exists {
		return nil, errs.NewMissing("my sharing id")
	}
	aggregatorSharingId, exists := sharingConfig.Reverse().Get(aggregatorIdentity)
	if !exists {
		return nil, errs.NewMissing("aggregator sharing id")
	}

	participant = &Cosigner{
		myAuthKey:             myAuthKey,
		mySharingId:           mySharingId,
		myShard:               myShard,
		preProcessingMaterial: ppm,
		initiatorIdentity:     initiatorIdentity,
		aggregatorIdentity:    aggregatorIdentity,
		aggregatorSharingId:   aggregatorSharingId,
		protocol:              protocol,
		prng:                  prng,
	}

	if err := types.ValidateThresholdSignatureProtocol(participant, protocol); err != nil {
		return nil, errs.WrapValidation(err, "couldn't construct non interactive cosigner")
	}
	return participant, nil
}

func validateCosignerInputs(protocol types.ThresholdSignatureProtocol, myAuthKey types.AuthKey, myShard *lindell17.Shard, ppm *lindell17.PreProcessingMaterial, initiator, aggregator types.IdentityKey, prng io.Reader) error {
	if err := types.ValidateThresholdSignatureProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config")
	}
	if err := types.ValidateAuthKey(myAuthKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if err := myShard.Validate(protocol, myAuthKey, false); err != nil {
		return errs.WrapValidation(err, "my shard")
	}
	if err := ppm.Validate(myAuthKey, protocol); err != nil {
		return errs.WrapValidation(err, "pre processing material")
	}
	if err := types.ValidateIdentityKey(initiator); err != nil {
		return errs.WrapValidation(err, "initiator")
	}
	if !ppm.PreSigners.Contains(initiator) {
		return errs.NewMembership("initiator is not a participant")
	}
	if err := types.ValidateIdentityKey(aggregator); err != nil {
		return errs.WrapValidation(err, "aggregator")
	}
	if !ppm.PreSigners.Contains(aggregator) {
		return errs.NewMembership("aggregator is not a participant")
	}
	if initiator.Equal(aggregator) {
		return errs.NewType("initiator can't be aggregator")
	}
	if !myAuthKey.Equal(initiator) && !myAuthKey.Equal(aggregator) {
		return errs.NewValue("i need to be either an initiator or an aggregator")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}
