package noninteractive_signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var _ types.ThresholdParticipant = (*PreGenParticipant)(nil)
var _ types.WithAuthKey = (*PreGenParticipant)(nil)

type PreGenParticipant struct {
	prng io.Reader

	Tau         int
	MyAuthKey   types.AuthKey
	Protocol    types.ThresholdProtocol
	mySharingId types.SharingID
	round       int
	state       *preGenState

	_ ds.Incomparable
}

func (p *PreGenParticipant) IdentityKey() types.IdentityKey {
	return p.MyAuthKey
}

func (p *PreGenParticipant) AuthKey() types.AuthKey {
	return p.MyAuthKey
}

func (p *PreGenParticipant) SharingId() types.SharingID {
	return p.mySharingId
}

type preGenState struct {
	ds          []curves.Scalar
	es          []curves.Scalar
	Commitments []*AttestedCommitmentToNoncePair

	_ ds.Incomparable
}

func NewPreGenParticipant(authKey types.AuthKey, protocol types.ThresholdProtocol, tau int, prng io.Reader) (*PreGenParticipant, error) {
	err := validateInputs(authKey, protocol, tau, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to validate inputs")
	}

	mySharingId, exists := types.DeriveSharingConfig(protocol.Participants()).LookUpRight(authKey)
	if !exists {
		return nil, errs.NewMissing("could not find my sharing id")
	}

	participant := &PreGenParticipant{
		prng:        prng,
		Tau:         tau,
		MyAuthKey:   authKey,
		Protocol:    protocol,
		mySharingId: mySharingId,
		round:       1,
		state:       &preGenState{},
	}

	if err := types.ValidateThresholdProtocol(participant, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct frost pregen participant")
	}
	return participant, nil
}

func validateInputs(authKey types.AuthKey, protocol types.ThresholdProtocol, tau int, prng io.Reader) error {
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol")
	}
	if tau <= 0 {
		return errs.NewArgument("tau is nonpositive")
	}
	if prng == nil {
		return errs.NewMissing("PRNG is nil")
	}
	return nil
}
