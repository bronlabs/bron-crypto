package setup

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/commitments"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashset"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

type Participant struct {
	prng io.Reader

	UniqueSessionId []byte
	Curve           curves.Curve
	MyIdentityKey   integration.IdentityKey
	MySharingId     int
	Participants    []integration.IdentityKey

	IdentityKeyToSharingId map[integration.IdentityHash]int

	state *State
	round int
}

type State struct {
	receivedSeeds map[integration.IdentityHash]commitments.Commitment
	sentSeeds     map[integration.IdentityHash]*committedSeedContribution
	transcript    transcripts.Transcript
}

type committedSeedContribution struct {
	seed       []byte
	commitment commitments.Commitment
	witness    commitments.Witness
}

func NewParticipant(curve curves.Curve, uniqueSessionId []byte, identityKey integration.IdentityKey, participants []integration.IdentityKey, transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
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
	for i, participant := range participants {
		if participant == nil {
			return nil, errs.NewIsNil("participant %d is nil", i)
		}
	}
	participantHashSet, err := hashset.NewHashSet(participants)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct participant hash set")
	}
	_, found := participantHashSet.Get(identityKey)
	if !found {
		return nil, errs.NewInvalidArgument("i'm not part of the participants")
	}
	_, identityKeyToSharingId, mySharingId := integration.DeriveSharingIds(identityKey, participants)
	if mySharingId == -1 {
		return nil, errs.NewMissing("my sharing id could not be found")
	}
	sortedParticipants := integration.SortIdentityKeys(participants)
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_KNOX_ZERO_SHARE_SETUP")
	}
	transcript.AppendMessages("zero share sampling setup", uniqueSessionId)

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
			receivedSeeds: map[integration.IdentityHash]commitments.Commitment{},
			sentSeeds:     map[integration.IdentityHash]*committedSeedContribution{},
		},
		round: 1,
	}, nil
}
