package setup

import (
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/commitments"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/gtank/merlin"
)

type Participant struct {
	prng io.Reader

	UniqueSessionId []byte
	Curve           *curves.Curve
	MyIdentityKey   integration.IdentityKey
	MySharingId     int
	Participants    []integration.IdentityKey

	IdentityKeyToSharingId map[integration.IdentityKey]int

	state *State
	round int
}

type State struct {
	r_i           curves.Scalar
	receivedSeeds map[integration.IdentityKey]commitments.Commitment
	sentSeeds     map[integration.IdentityKey]*committedSeedContribution
	transcript    *merlin.Transcript
}

type committedSeedContribution struct {
	seed       []byte
	commitment commitments.Commitment
	witness    commitments.Witness
}

func NewParticipant(curve *curves.Curve, uniqueSessionId []byte, identityKey integration.IdentityKey, participants []integration.IdentityKey, transcript *merlin.Transcript, prng io.Reader) (*Participant, error) {
	if curve == nil {
		return nil, errs.NewInvalidArgument("curve is nil")
	}
	if identityKey == nil {
		return nil, errs.NewInvalidArgument("my identity key is nil")
	}
	if uniqueSessionId == nil {
		return nil, errs.NewInvalidArgument("session id is nil")
	}
	if len(participants) < 2 {
		return nil, errs.NewInvalidArgument("need at least 2 participants")
	}
	participantHashSet, err := integration.NewPresentParticipantSet(participants)
	if err != nil {
		return nil, err
	}
	if !participantHashSet.Exist(identityKey) {
		return nil, errs.NewInvalidArgument("i'm not part of the participants")
	}
	_, identityKeyToSharingId, mySharingId := integration.DeriveSharingIds(identityKey, participants)
	if mySharingId == -1 {
		return nil, errs.NewMissing("my sharing id could not be found")
	}
	sortedParticipants := integration.SortIdentityKeys(participants)
	if transcript == nil {
		transcript = merlin.NewTranscript("COPPER_KNOX_ZERO_SHARE_SETUP")
	}
	transcript.AppendMessage([]byte("zero share sampling setup"), uniqueSessionId)

	return &Participant{
		prng:                   prng,
		Curve:                  curve,
		MyIdentityKey:          identityKey,
		MySharingId:            mySharingId,
		Participants:           sortedParticipants,
		IdentityKeyToSharingId: identityKeyToSharingId,
		UniqueSessionId:        uniqueSessionId,
		state: &State{
			transcript:    transcript,
			receivedSeeds: map[integration.IdentityKey]commitments.Commitment{},
			sentSeeds:     map[integration.IdentityKey]*committedSeedContribution{},
		},
		round: 1,
	}, nil
}
