package setup

import (
	"fmt"
	"io"
	"sort"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const transcriptLabel = "COPPER_KRYPTON_PRZS_ZERO_SETUP-"

var _ types.MPCParticipant = (*Participant)(nil)

type Participant struct {
	prng io.Reader

	SessionId          []byte
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
	receivedSeeds ds.Map[types.IdentityKey, commitments.Commitment]
	sentSeeds     ds.Map[types.IdentityKey, *committedSeedContribution]
	transcript    transcripts.Transcript

	_ ds.Incomparable
}

type committedSeedContribution struct {
	seed       []byte
	commitment commitments.Commitment
	witness    commitments.Witness

	_ ds.Incomparable
}

func NewParticipant(sessionId []byte, authKey types.AuthKey, protocol types.MPCProtocol, transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
	err := validateInputs(sessionId, authKey, protocol, prng)
	if err != nil {
		return nil, errs.NewArgument("invalid input arguments")
	}
	identitySpace := types.NewIdentitySpace(protocol.Participants())
	sortedParticipants := types.ByPublicKey(protocol.Participants().List())
	sort.Sort(sortedParticipants)

	dst := fmt.Sprintf("%s-%s", transcriptLabel, protocol.Curve().Name())
	transcript, sessionId, err = hagrid.InitialiseProtocol(transcript, sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	if prng == nil {
		return nil, errs.NewArgument("prng is nil")
	}
	result := &Participant{
		prng:               prng,
		myAuthKey:          authKey,
		SortedParticipants: sortedParticipants,
		IdentitySpace:      identitySpace,
		SessionId:          sessionId,
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

func validateInputs(sessionId []byte, identityKey types.IdentityKey, protocol types.MPCProtocol, prng io.Reader) error {
	if err := types.ValidateIdentityKey(identityKey); err != nil {
		return errs.WrapValidation(err, "identity key")
	}
	if err := types.ValidateMPCProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config is invalid")
	}
	if len(sessionId) == 0 {
		return errs.NewArgument("unique session id is empty")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	if len(sessionId) == 0 {
		return errs.NewIsZero("sessionId length is zero")
	}
	if !curveutils.AllIdentityKeysWithSameCurve(identityKey.PublicKey().Curve(), protocol.Participants().List()...) {
		return errs.NewCurve("authKey and participants have different curves")
	}
	return nil
}
