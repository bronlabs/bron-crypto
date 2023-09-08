package agreeonrandom

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/base/curves"
	"github.com/copperexchange/knox-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/knox-primitives/pkg/base/errs"
	"github.com/copperexchange/knox-primitives/pkg/base/integration"
	"github.com/copperexchange/knox-primitives/pkg/base/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/commitments"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

type Participant struct {
	prng io.Reader

	Curve               curves.Curve
	MyIdentityKey       integration.IdentityKey
	SharingIdToIdentity map[int]integration.IdentityKey

	state *State
	round int

	_ helper_types.Incomparable
}

type State struct {
	transcript transcripts.Transcript
	r_i        curves.Scalar

	witness             commitments.Witness
	receivedCommitments map[helper_types.IdentityHash]commitments.Commitment

	_ helper_types.Incomparable
}

func NewParticipant(curve curves.Curve, identityKey integration.IdentityKey, participants *hashset.HashSet[integration.IdentityKey], transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
	err := validateInputs(curve, identityKey, participants, prng)
	if err != nil {
		return nil, errs.NewInvalidArgument("invalid input arguments")
	}
	// if you pass presentParticipants to below, sharing ids will be different
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_KNOX_AGREE_ON_RANDOM")
	}
	sharingIdToIdentity, _, _ := integration.DeriveSharingIds(identityKey, participants)
	return &Participant{
		prng:                prng,
		MyIdentityKey:       identityKey,
		round:               1,
		Curve:               curve,
		SharingIdToIdentity: sharingIdToIdentity,
		state: &State{
			transcript:          transcript,
			receivedCommitments: map[helper_types.IdentityHash]commitments.Commitment{},
		},
	}, nil
}

func validateInputs(curve curves.Curve, identityKey integration.IdentityKey, participants *hashset.HashSet[integration.IdentityKey], prng io.Reader) error {
	if curve == nil {
		return errs.NewInvalidArgument("curve is nil")
	}
	if identityKey == nil {
		return errs.NewInvalidArgument("my identity key is nil")
	}
	if participants.Len() < 2 {
		return errs.NewInvalidArgument("need at least 2 participants")
	}
	for i, participant := range participants.Iter() {
		if participant == nil {
			return errs.NewIsNil("participant %x is nil", i)
		}
	}
	if prng == nil {
		return errs.NewInvalidArgument("prng is nil")
	}
	_, found := participants.Get(identityKey)
	if !found {
		return errs.NewInvalidArgument("i'm not part of the participants")
	}
	return nil
}
