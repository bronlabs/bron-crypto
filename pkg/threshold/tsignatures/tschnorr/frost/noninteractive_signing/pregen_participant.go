package noninteractive_signing

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
)

var _ types.ThresholdParticipant = (*PreGenParticipant)(nil)

type PreGenParticipant struct {
	// Base Participant
	myAuthKey  types.AuthKey
	Prng       io.Reader
	Protocol   types.ThresholdProtocol
	Round      int
	SessionId  []byte
	Transcript transcripts.Transcript

	// Threshold Participant
	mySharingId types.SharingID

	Tau int

	state *preGenState

	_ ds.Incomparable
}

func (p *PreGenParticipant) IdentityKey() types.IdentityKey {
	return p.myAuthKey
}

func (p *PreGenParticipant) AuthKey() types.AuthKey {
	return p.myAuthKey
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

	mySharingId, exists := types.DeriveSharingConfig(protocol.Participants()).Reverse().Get(authKey)
	if !exists {
		return nil, errs.NewMissing("could not find my sharing id")
	}

	participant := &PreGenParticipant{
		myAuthKey:   authKey,
		Prng:        prng,
		Protocol:    protocol,
		Round:       1,
		mySharingId: mySharingId,
		Tau:         tau,
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
