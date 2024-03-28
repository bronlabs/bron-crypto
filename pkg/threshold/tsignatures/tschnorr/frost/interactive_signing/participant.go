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
	types.Participant[types.ThresholdSignatureProtocol]

	myAuthKey   types.AuthKey
	mySharingId types.SharingID
	shard       *frost.Shard

	sharingConfig types.SharingConfig
	quorum        ds.Set[types.IdentityKey]

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
	return ic.Protocol().Participants().Contains(ic.IdentityKey())
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
		Participant:   types.NewBaseParticipant(prng, protocol, 1, nil, nil),
		myAuthKey:     authKey,
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
	if err := types.ValidateThresholdSignatureProtocol(protocol); err != nil {
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
