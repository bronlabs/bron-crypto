package agreeonrandom

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const transcriptLabel = "COPPER_KRYPTON_AGREE_ON_RANDOM-"

var _ types.MPCParticipant = (*Participant)(nil)

type Participant struct {
	*types.BaseParticipant[types.MPCProtocol]

	myAuthKey     types.AuthKey
	IdentitySpace types.IdentitySpace

	state *State

	_ ds.Incomparable
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.myAuthKey
}

type State struct {
	r_i                 curves.Scalar
	witness             commitments.Witness
	receivedCommitments ds.Map[types.IdentityKey, commitments.Commitment]

	_ ds.Incomparable
}

func NewParticipant(authKey types.AuthKey, protocol types.MPCProtocol, transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
	if err := validateInputs(authKey, protocol, prng); err != nil {
		return nil, errs.WrapArgument(err, "invalid input arguments")
	}
	// if you pass presentParticipants to below, sharing ids will be different
	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptLabel, nil)
	}

	identitySpace := types.NewIdentitySpace(protocol.Participants())
	participant := &Participant{
		BaseParticipant: types.NewBaseParticipant(prng, protocol, 1, nil, transcript),
		myAuthKey:       authKey,
		IdentitySpace:   identitySpace,
		state: &State{
			receivedCommitments: hashmap.NewHashableHashMap[types.IdentityKey, commitments.Commitment](),
		},
	}

	if err := types.ValidateMPCProtocol(participant, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct a new participant")
	}

	return participant, nil
}

func validateInputs(authKey types.AuthKey, protocol types.MPCProtocol, prng io.Reader) error {
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if err := types.ValidateMPCProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, " mpc protocol")
	}
	if prng == nil {
		return errs.NewIsNil("prng")
	}
	return nil
}
