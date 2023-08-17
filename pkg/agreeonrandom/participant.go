package agreeonrandom

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashset"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

type Participant struct {
	prng io.Reader

	Curve         curves.Curve
	MyIdentityKey integration.IdentityKey

	state *State
	round int

	_ helper_types.Incomparable
}

type State struct {
	transcript transcripts.Transcript
	r_i        curves.Scalar

	_ helper_types.Incomparable
}

func NewParticipant(curve curves.Curve, identityKey integration.IdentityKey, participants []integration.IdentityKey, transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
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
	presentParticipantHashSet, err := hashset.NewHashSet(participants)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't construct hashset of participants")
	}
	_, found := presentParticipantHashSet.Get(identityKey)
	if !found {
		return nil, errs.NewInvalidArgument("i'm not part of the participants")
	}

	// if you pass presentParticipants to below, sharing ids will be different
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_KNOX_AGREE_ON_RANDOM")
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
