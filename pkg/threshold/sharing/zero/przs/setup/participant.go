package setup

import (
	"io"
	"sort"

	"github.com/copperexchange/krypton/pkg/base/curves"
	"github.com/copperexchange/krypton/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton/pkg/base/errs"
	"github.com/copperexchange/krypton/pkg/base/types"
	"github.com/copperexchange/krypton/pkg/base/types/integration"
	"github.com/copperexchange/krypton/pkg/commitments"
	"github.com/copperexchange/krypton/pkg/transcripts"
	"github.com/copperexchange/krypton/pkg/transcripts/hagrid"
)

type Participant struct {
	prng io.Reader

	UniqueSessionId    []byte
	Curve              curves.Curve
	MyIdentityKey      integration.IdentityKey
	MySharingId        int
	SortedParticipants []integration.IdentityKey

	IdentityKeyToSharingId map[types.IdentityHash]int

	state *State
	round int

	_ types.Incomparable
}

type State struct {
	receivedSeeds map[types.IdentityHash]commitments.Commitment
	sentSeeds     map[types.IdentityHash]*committedSeedContribution
	transcript    transcripts.Transcript

	_ types.Incomparable
}

type committedSeedContribution struct {
	seed       []byte
	commitment commitments.Commitment
	witness    commitments.Witness

	_ types.Incomparable
}

func NewParticipant(curve curves.Curve, uniqueSessionId []byte, identityKey integration.IdentityKey, participants *hashset.HashSet[integration.IdentityKey], transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
	if curve == nil {
		return nil, errs.NewInvalidArgument("curve is nil")
	}
	if identityKey == nil {
		return nil, errs.NewInvalidArgument("my identity key is nil")
	}
	if len(uniqueSessionId) == 0 {
		return nil, errs.NewInvalidArgument("session id is nil")
	}
	if participants.Len() < 2 {
		return nil, errs.NewInvalidArgument("need at least 2 participants")
	}
	for i, participant := range participants.Iter() {
		if participant == nil {
			return nil, errs.NewIsNil("participant %x is nil", i)
		}
	}
	_, found := participants.Get(identityKey)
	if !found {
		return nil, errs.NewInvalidArgument("i'm not part of the participants")
	}
	_, identityKeyToSharingId, mySharingId := integration.DeriveSharingIds(identityKey, participants)
	if mySharingId == -1 {
		return nil, errs.NewMissing("my sharing id could not be found")
	}
	sortedParticipants := integration.ByPublicKey(participants.List())
	sort.Sort(sortedParticipants)
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_KRYPTON_ZERO_SHARE_SETUP", nil)
	}
	transcript.AppendMessages("zero share sampling setup", uniqueSessionId)
	if prng == nil {
		return nil, errs.NewInvalidArgument("prng is nil")
	}
	return &Participant{
		prng:                   prng,
		Curve:                  curve,
		MyIdentityKey:          identityKey,
		MySharingId:            mySharingId,
		SortedParticipants:     sortedParticipants,
		IdentityKeyToSharingId: identityKeyToSharingId,
		UniqueSessionId:        uniqueSessionId,
		state: &State{
			transcript:    transcript,
			receivedSeeds: map[types.IdentityHash]commitments.Commitment{},
			sentSeeds:     map[types.IdentityHash]*committedSeedContribution{},
		},
		round: 1,
	}, nil
}
