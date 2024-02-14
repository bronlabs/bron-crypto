package setup

import (
	"io"
	"sort"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

var _ types.MPCParticipant = (*Participant)(nil)

type Participant struct {
	prng io.Reader

	UniqueSessionId    []byte
	Curve              curves.Curve
	myAuthKey          types.AuthKey
	SortedParticipants []types.IdentityKey

	IdentitySpace types.IdentitySpace

	state *State
	round int

	_ ds.Incomparable
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.myAuthKey
}

type State struct {
	receivedSeeds ds.HashMap[types.IdentityKey, commitments.Commitment]
	sentSeeds     ds.HashMap[types.IdentityKey, *committedSeedContribution]
	transcript    transcripts.Transcript

	_ ds.Incomparable
}

type committedSeedContribution struct {
	seed       []byte
	commitment commitments.Commitment
	witness    commitments.Witness

	_ ds.Incomparable
}

func NewParticipant(uniqueSessionId []byte, authKey types.AuthKey, protocol types.MPCProtocol, transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
	err := validateInputs(uniqueSessionId, authKey, protocol, prng)
	if err != nil {
		return nil, errs.NewArgument("invalid input arguments")
	}
	identitySpace := types.NewIdentitySpace(protocol.Participants())
	sortedParticipants := types.ByPublicKey(protocol.Participants().List())
	sort.Sort(sortedParticipants)
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_KRYPTON_ZERO_SHARE_SETUP", nil)
	}
	transcript.AppendMessages("zero share sampling setup", uniqueSessionId)
	if prng == nil {
		return nil, errs.NewArgument("prng is nil")
	}
	result := &Participant{
		prng:               prng,
		myAuthKey:          authKey,
		SortedParticipants: sortedParticipants,
		IdentitySpace:      identitySpace,
		UniqueSessionId:    uniqueSessionId,
		state: &State{
			transcript:    transcript,
			receivedSeeds: hashmap.NewHashableHashMap[types.IdentityKey, commitments.Commitment](),
			sentSeeds:     hashmap.NewHashableHashMap[types.IdentityKey, *committedSeedContribution](),
		},
		round: 1,
	}
	if err := types.ValidateMPCProtocol(result, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct the participant")
	}
	return result, nil
}

func validateInputs(uniqueSessionId []byte, identityKey types.IdentityKey, protocol types.MPCProtocol, prng io.Reader) error {
	if err := types.ValidateIdentityKey(identityKey); err != nil {
		return errs.WrapValidation(err, "identity key")
	}
	if err := types.ValidateMPCProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "cohort config is invalid")
	}
	if len(uniqueSessionId) == 0 {
		return errs.NewArgument("unique session id is empty")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	if len(uniqueSessionId) == 0 {
		return errs.NewIsZero("sid length is zero")
	}
	return nil
}
