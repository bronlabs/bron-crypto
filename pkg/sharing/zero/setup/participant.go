package setup

import (
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/commitments"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/zero"
	"github.com/gtank/merlin"
)

type Participant struct {
	prng io.Reader

	Curve         *curves.Curve
	MyIdentityKey integration.IdentityKey
	MySharingId   int
	Participants  []integration.IdentityKey

	SharingIdToIdentityKey map[int]integration.IdentityKey
	IdentityKeyToSharingId map[integration.IdentityKey]int

	state *State
	round int
}

type State struct {
	r_i           curves.Scalar
	receivedSeeds map[integration.IdentityKey]zero.Seed
	sentSeeds     map[integration.IdentityKey]*committedSeedContribution
	transcript    *merlin.Transcript
}

type committedSeedContribution struct {
	seed       []byte
	commitment commitments.Commitment
	witness    commitments.Witness
}

func NewParticipant(curve *curves.Curve, identityKey integration.IdentityKey, participants []integration.IdentityKey, transcript *merlin.Transcript, prng io.Reader) (*Participant, error) {
	if curve == nil {
		return nil, errs.NewInvalidArgument("curve is nil")
	}
	if identityKey == nil {
		return nil, errs.NewInvalidArgument("my identity key is nil")
	}
	participantHashSet := map[integration.IdentityKey]bool{}
	for i, participant := range participants {
		if participant == nil {
			return nil, errs.NewInvalidArgument("participant %d is nil", i)
		}
		if _, exists := participantHashSet[participant]; exists {
			return nil, errs.NewDuplicate("participant %d is duplicate", i)
		}
		participantHashSet[participant] = true
	}
	if _, exists := participantHashSet[identityKey]; !exists {
		return nil, errs.NewInvalidArgument("i'm not part of the participants")
	}
	sharingIdToIdentityKey, identityKeyToSharingId, mySharingId := integration.DeriveSharingIds(identityKey, participants)
	if mySharingId == -1 {
		return nil, errs.NewMissing("my sharing id could not be found")
	}
	sortedParticipants := integration.SortIdentityKeys(participants)

	if transcript == nil {
		transcript = merlin.NewTranscript("COPPER_KNOX_ZERO_SHARE_SETUP")
	}

	return &Participant{
		prng:                   prng,
		Curve:                  curve,
		MyIdentityKey:          identityKey,
		MySharingId:            mySharingId,
		Participants:           sortedParticipants,
		SharingIdToIdentityKey: sharingIdToIdentityKey,
		IdentityKeyToSharingId: identityKeyToSharingId,
		state: &State{
			transcript: transcript,
		},
		round: 1,
	}, nil
}
