package setup

import (
	"fmt"
	"io"
	"sort"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/roundbased"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	hashcommitments "github.com/copperexchange/krypton-primitives/pkg/commitments/hash"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/rprzs"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const transcriptLabel = "COPPER_KRYPTON_PRZS_ZERO_SETUP-"

var _ types.Participant = (*Participant)(nil)

type Participant struct {
	// Base participant
	myAuthKey  types.AuthKey
	Prng       io.Reader
	Protocol   types.Protocol
	Round      int
	SessionId  []byte
	Transcript transcripts.Transcript

	SortedParticipants []types.IdentityKey
	IdentitySpace      types.IdentitySpace

	state *State

	_ ds.Incomparable
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.myAuthKey
}

type State struct {
	receivedSeeds ds.Map[types.IdentityKey, *hashcommitments.Commitment]
	sentSeeds     ds.Map[types.IdentityKey, *committedSeedContribution]

	_ ds.Incomparable
}

type committedSeedContribution struct {
	seed       []byte
	commitment *hashcommitments.Commitment
	opening    *hashcommitments.Opening

	_ ds.Incomparable
}

func NewParticipant(sessionId []byte, authKey types.AuthKey, protocol types.Protocol, transcript transcripts.Transcript, prng io.Reader) (*Participant, error) {
	err := validateInputs(sessionId, authKey, protocol, prng)
	if err != nil {
		return nil, errs.NewArgument("invalid input arguments")
	}
	identitySpace := types.NewIdentitySpace(protocol.Participants())
	sortedParticipants := types.ByPublicKey(protocol.Participants().List())
	sort.Sort(sortedParticipants)

	dst := fmt.Sprintf("%s-%s", transcriptLabel, protocol.Curve().Name())
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, prng)
	}
	boundSessionId, err := transcript.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	if prng == nil {
		return nil, errs.NewArgument("prng is nil")
	}
	result := &Participant{
		myAuthKey:          authKey,
		Prng:               prng,
		Protocol:           protocol,
		SessionId:          boundSessionId,
		Round:              1,
		Transcript:         transcript,
		SortedParticipants: sortedParticipants,
		IdentitySpace:      identitySpace,
		state: &State{
			receivedSeeds: hashmap.NewHashableHashMap[types.IdentityKey, *hashcommitments.Commitment](),
			sentSeeds:     hashmap.NewHashableHashMap[types.IdentityKey, *committedSeedContribution](),
		},
	}
	if err := types.ValidateProtocol(result, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct the participant")
	}
	return result, nil
}

func validateInputs(sessionId []byte, identityKey types.IdentityKey, protocol types.Protocol, prng io.Reader) error {
	if err := types.ValidateIdentityKey(identityKey); err != nil {
		return errs.WrapValidation(err, "identity key")
	}
	if err := types.ValidateProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config is invalid")
	}
	if len(sessionId) == 0 {
		return errs.NewArgument("unique session id is empty")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	if !curveutils.AllIdentityKeysWithSameCurve(identityKey.PublicKey().Curve(), protocol.Participants().List()...) {
		return errs.NewCurve("authKey and participants have different curves")
	}
	return nil
}

func (p *Participant) Run(router roundbased.MessageRouter) (rprzs.PairWiseSeeds, error) {
	r1b := roundbased.NewUnicastRound[*Round1P2P](p.IdentityKey(), 1, router)
	r2b := roundbased.NewUnicastRound[*Round2P2P](p.IdentityKey(), 2, router)

	// round 1
	r1uo, err := p.Round1()
	if err != nil {
		return nil, errs.WrapFailed(err, "round 1 failed")
	}
	r1b.UnicastOut() <- r1uo

	// round 2
	r2uo, err := p.Round2(<-r1b.UnicastIn())
	if err != nil {
		return nil, errs.WrapFailed(err, "round 2 failed")
	}
	r2b.UnicastOut() <- r2uo

	// round 3
	r3Out, err := p.Round3(<-r2b.UnicastIn())
	if err != nil {
		return nil, errs.WrapFailed(err, "round 3 failed")
	}
	return r3Out, nil
}
