package interactive_signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/roundbased"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost/interactive_signing/aggregation"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

var _ types.ThresholdSignatureParticipant = (*Cosigner)(nil)

type Cosigner struct {
	// Base Participant
	myAuthKey  types.AuthKey
	Prng       io.Reader
	Protocol   types.ThresholdSignatureProtocol
	Round      int
	SessionId  []byte
	Transcript transcripts.Transcript

	// Threshold Participant
	mySharingId   types.SharingID
	sharingConfig types.SharingConfig

	shard  *frost.Shard
	quorum ds.Set[types.IdentityKey]

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
	return ic.Protocol.Participants().Contains(ic.IdentityKey())
}

type State struct {
	d_i curves.Scalar
	D_i curves.Point
	e_i curves.Scalar
	E_i curves.Point

	aggregation *aggregation.SignatureAggregatorParameters

	_ ds.Incomparable
}

func NewInteractiveCosigner(authKey types.AuthKey, quorum ds.Set[types.IdentityKey], shard *frost.Shard, protocol types.ThresholdSignatureProtocol, prng io.Reader) (*Cosigner, error) {
	err := validateInputs(authKey, quorum, shard, protocol, prng)
	if err != nil {
		return nil, errs.WrapArgument(err, "invalid input arguments")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.Reverse().Get(authKey)
	if !exists {
		return nil, errs.NewMissing("could not find my sharing id")
	}

	cosigner := &Cosigner{
		myAuthKey:     authKey,
		Prng:          prng,
		Protocol:      protocol,
		Round:         1,
		SessionId:     nil,
		Transcript:    nil,
		shard:         shard,
		quorum:        quorum,
		sharingConfig: sharingConfig,
		mySharingId:   mySharingId,
		state:         &State{},
	}

	if cosigner.IsSignatureAggregator() {
		cosigner.state.aggregation = &aggregation.SignatureAggregatorParameters{}
	}

	if err := types.ValidateThresholdSignatureProtocol(cosigner, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct a frost interactive cosigner")
	}

	return cosigner, nil
}

func validateInputs(authKey types.AuthKey, quorum ds.Set[types.IdentityKey], shard *frost.Shard, protocol types.ThresholdSignatureProtocol, prng io.Reader) error {
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "my auth key")
	}
	if err := types.ValidateThresholdSignatureProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config is invalid")
	}
	if err := shard.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "shard")
	}
	if quorum == nil {
		return errs.NewIsNil("session participants")
	}
	if !quorum.IsSubSet(protocol.Participants()) {
		return errs.NewMembership("session participants are not a subset of the total participants")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}

func (ic *Cosigner) Run(router roundbased.MessageRouter, msg []byte) (*frost.PartialSignature, error) {
	r1b := roundbased.NewBroadcastRound[*Round1Broadcast](ic.IdentityKey(), 1, router)

	// round 1
	r1Out, err := ic.Round1()
	if err != nil {
		return nil, errs.WrapFailed(err, "round 1 failed")
	}
	r1b.BroadcastOut() <- r1Out

	// round 2
	r2Out, err := ic.Round2(<-r1b.BroadcastIn(), msg)
	if err != nil {
		return nil, errs.WrapFailed(err, "round 2 failed")
	}

	return r2Out, nil
}
