package interactive_signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost/interactive_signing/aggregation"
)

var _ types.ThresholdSignatureParticipant = (*Cosigner)(nil)

type Cosigner struct {
	prng io.Reader

	myAuthKey   types.AuthKey
	mySharingId types.SharingID
	shard       *frost.Shard

	protocol            types.ThresholdSignatureProtocol
	sharingConfig       types.SharingConfig
	sessionParticipants ds.HashSet[types.IdentityKey]

	round int
	state *State

	_ ds.Incomparable
}

func (ic *Cosigner) IdentityKey() types.IdentityKey {
	return ic.myAuthKey
}

func (ic *Cosigner) SharingId() types.SharingID {
	return ic.mySharingId
}

func (ic *Cosigner) IsSignatureAggregator() bool {
	return ic.protocol.Participants().Contains(ic.IdentityKey())
}

type State struct {
	d_i curves.Scalar
	D_i curves.Point
	e_i curves.Scalar
	E_i curves.Point

	aggregation *aggregation.SignatureAggregatorParameters

	_ ds.Incomparable
}

func NewInteractiveCosigner(authKey types.AuthKey, sessionParticipants ds.HashSet[types.IdentityKey], shard *frost.Shard, protocol types.ThresholdSignatureProtocol, prng io.Reader) (*Cosigner, error) {
	err := validateInputs(authKey, sessionParticipants, shard, protocol, prng)
	if err != nil {
		return nil, errs.WrapArgument(err, "invalid input arguments")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.LookUpRight(authKey)
	if !exists {
		return nil, errs.NewMissing("could not find my sharing id")
	}

	cosigner := &Cosigner{
		myAuthKey:           authKey,
		protocol:            protocol,
		shard:               shard,
		sessionParticipants: sessionParticipants,
		prng:                prng,
		sharingConfig:       sharingConfig,
		mySharingId:         mySharingId,
		state:               &State{},
		round:               1,
	}

	if cosigner.IsSignatureAggregator() {
		cosigner.state.aggregation = &aggregation.SignatureAggregatorParameters{}
	}

	if err := types.ValidateThresholdSignatureProtocol(cosigner, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct a frost interactive cosigner")
	}

	return cosigner, nil
}

func validateInputs(authKey types.AuthKey, sessionParticipants ds.HashSet[types.IdentityKey], shard *frost.Shard, protocol types.ThresholdSignatureProtocol, prng io.Reader) error {
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "my auth key")
	}
	if err := types.ValidateThresholdSignatureProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config is invalid")
	}
	if err := shard.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "shard")
	}
	if sessionParticipants == nil {
		return errs.NewIsNil("session participants")
	}
	if !sessionParticipants.IsSubSet(protocol.Participants()) {
		return errs.NewMembership("session participants are not a subset of the total participants")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}
