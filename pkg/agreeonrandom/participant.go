package agreeonrandom

import (
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/datastructures/hashmap"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/gtank/merlin"
)

type Participant struct {
	prng io.Reader

	Curve         *curves.Curve
	MyIdentityKey integration.IdentityKey

	state *State
	round int
}

type State struct {
	transcript *merlin.Transcript
	r_i        curves.Scalar
}

func NewParticipant(curve *curves.Curve, identityKey integration.IdentityKey, participants []integration.IdentityKey, transcript *merlin.Transcript, prng io.Reader) (*Participant, error) {
	if curve == nil {
		return nil, errs.NewInvalidArgument("curve is nil")
	}
	if identityKey == nil {
		return nil, errs.NewInvalidArgument("my identity key is nil")
	}
	if len(participants) < 2 {
		return nil, errs.NewInvalidArgument("need at least 2 participants")
	}
	for i, participant := range participants {
		if participant == nil {
			return nil, errs.NewIsNil("participant %d is nil", i)
		}
	}
	presentParticipantHashSet, err := hashmap.NewHashmap(participants)
	if err != nil {
		return nil, err
	}
	_, found := hashmap.Get(presentParticipantHashSet, identityKey)
	if !found {
		return nil, errs.NewInvalidArgument("i'm not part of the participants")
	}

	// if you pass presentParticipants to below, sharing ids will be different
	if transcript == nil {
		transcript = merlin.NewTranscript("COPPER_KNOX_AGREE_ON_RANDOM")
	}
	return &Participant{
		prng:          prng,
		MyIdentityKey: identityKey,
		round:         1,
		Curve:         curve,
		state: &State{
			transcript: transcript,
		},
	}, nil
}
