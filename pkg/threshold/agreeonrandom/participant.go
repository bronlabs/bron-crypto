package agreeonrandom

import (
	"io"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	hashcommitments "github.com/bronlabs/krypton-primitives/pkg/commitments/hash"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts/hagrid"
)

const transcriptLabel = "KRYPTON_AGREE_ON_RANDOM-"

var _ types.Participant = (*Participant)(nil)

type Participant struct {
	// Base participant
	myAuthKey  types.AuthKey
	Protocol   types.Protocol
	Prng       io.Reader
	Round      int
	Transcript transcripts.Transcript

	state *State

	_ ds.Incomparable
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.myAuthKey
}

type State struct {
	r_i                 curves.Scalar
	opening             hashcommitments.Witness
	receivedCommitments ds.Map[types.IdentityKey, hashcommitments.Commitment]

	_ ds.Incomparable
}

func NewParticipant(authKey types.AuthKey, protocol types.Protocol, transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
	if err := validateInputs(authKey, protocol, prng); err != nil {
		return nil, errs.WrapArgument(err, "invalid input arguments")
	}
	// if you pass presentParticipants to below, sharing ids will be different
	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptLabel, nil)
	}

	participant := &Participant{
		Prng:       prng,
		myAuthKey:  authKey,
		Round:      1,
		Protocol:   protocol,
		Transcript: transcript,
		state: &State{
			receivedCommitments: hashmap.NewHashableHashMap[types.IdentityKey, hashcommitments.Commitment](),
		},
	}

	if err := types.ValidateProtocol(participant, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct a new participant")
	}

	return participant, nil
}

func validateInputs(authKey types.AuthKey, protocol types.Protocol, prng io.Reader) error {
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if err := types.ValidateProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, " protocol")
	}
	if prng == nil {
		return errs.NewIsNil("prng")
	}
	return nil
}
