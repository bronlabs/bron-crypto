package noninteractive

import (
	"fmt"
	"io"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/sample"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/mult"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/signing"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const transcriptLabel = "COPPER_KRYPTON_PREGEN_DKLS24-"

var _ signing.Participant = (*PreGenParticipant)(nil)
var _ types.ThresholdParticipant = (*PreGenParticipant)(nil) // only threshold piece of the protocol is important.

type PreGenParticipant struct {
	prng io.Reader

	myAuthKey   types.AuthKey
	mySharingId types.SharingID
	shard       *dkls24.Shard

	sessionId     []byte
	protocol      types.ThresholdProtocol
	sharingConfig types.SharingConfig
	PreSigners    ds.Set[types.IdentityKey]

	transcript transcripts.Transcript
	state      *signing.SignerState
	round      int

	_ ds.Incomparable
}

func (p *PreGenParticipant) Shard() *dkls24.Shard {
	return p.shard
}

func (p *PreGenParticipant) Protocol() types.ThresholdProtocol {
	return p.protocol
}

func (p *PreGenParticipant) SharingConfig() types.SharingConfig {
	return p.sharingConfig
}

func (p *PreGenParticipant) Prng() io.Reader {
	return p.prng
}

func (p *PreGenParticipant) SessionId() []byte {
	return p.sessionId
}

func (p *PreGenParticipant) IdentityKey() types.IdentityKey {
	return p.myAuthKey
}

func (p *PreGenParticipant) SharingId() types.SharingID {
	return p.mySharingId
}

func (p *PreGenParticipant) IsSignatureAggregator() bool {
	return p.Protocol().Participants().Contains(p.IdentityKey())
}

func NewPreGenParticipant(sessionId []byte, myAuthKey types.AuthKey, preSigners ds.Set[types.IdentityKey], myShard *dkls24.Shard, protocol types.ThresholdProtocol, transcript transcripts.Transcript, prng io.Reader, seededPrng csprng.CSPRNG) (participant *PreGenParticipant, err error) {
	if err := validateInputs(sessionId, myAuthKey, protocol, myShard, preSigners); err != nil {
		return nil, errs.WrapArgument(err, "could not validate input")
	}

	dst := fmt.Sprintf("%s-%s", transcriptLabel, protocol.Curve().Name())
	transcript, sessionId, err = hagrid.InitialiseProtocol(transcript, sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.Reverse().Get(myAuthKey)
	if !exists {
		return nil, errs.NewMissing("could not find my sharing id")
	}

	// step 0.2
	zeroShareSamplingParty, err := sample.NewParticipant(sessionId, myAuthKey, myShard.PairwiseSeeds, protocol, preSigners, seededPrng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct zero share sampling party")
	}

	// step 0.3
	multipliers := hashmap.NewHashableHashMap[types.IdentityKey, *signing.Multiplication]()
	for participant := range preSigners.Iter() {
		if participant.Equal(myAuthKey) {
			continue
		}
		otProtocol, err := types.NewMPCProtocol(protocol.Curve(), hashset.NewHashableHashSet(participant, myAuthKey.(types.IdentityKey)))
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct ot protocol config for me and %s", participant.String())
		}
		seedOtResults, exists := myShard.PairwiseBaseOTs.Get(participant)
		if !exists {
			return nil, errs.NewMissing("missing ot config for participant %s", participant.String())
		}
		alice, err := mult.NewAlice(myAuthKey, otProtocol, seedOtResults.AsReceiver, sessionId, prng, seededPrng, transcript.Clone())
		if err != nil {
			return nil, errs.WrapFailed(err, "alice construction for participant %s", participant.String())
		}
		bob, err := mult.NewBob(myAuthKey, otProtocol, seedOtResults.AsSender, sessionId, prng, seededPrng, transcript.Clone())
		if err != nil {
			return nil, errs.WrapFailed(err, "bob construction for participant %s", participant.String())
		}
		multipliers.Put(participant, &signing.Multiplication{
			Alice: alice,
			Bob:   bob,
		})
	}

	participant = &PreGenParticipant{
		myAuthKey:  myAuthKey,
		protocol:   protocol,
		shard:      myShard,
		sessionId:  sessionId,
		prng:       prng,
		transcript: transcript,
		state: &signing.SignerState{
			Protocols: &signing.SubProtocols{
				ZeroShareSampling: zeroShareSamplingParty,
				Multiplication:    multipliers,
			},
		},
		mySharingId:   mySharingId,
		sharingConfig: sharingConfig,
		PreSigners:    preSigners,
		round:         1,
	}

	if err := types.ValidateThresholdProtocol(participant, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct a lindell22 pregen participant")
	}

	return participant, nil
}

func validateInputs(sessionId []byte, authKey types.AuthKey, protocol types.ThresholdProtocol, shard *dkls24.Shard, preSigners ds.Set[types.IdentityKey]) error {
	if len(sessionId) == 0 {
		return errs.NewLength("invalid session id: %s", sessionId)
	}
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "threshold signature protocol config")
	}
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if err := shard.Validate(protocol, authKey); err != nil {
		return errs.WrapValidation(err, "could not validate shard")
	}
	if preSigners == nil {
		return errs.NewIsNil("preSigners")
	}
	if preSigners.Size() < int(protocol.Threshold()) {
		return errs.NewSize("not enough session participants: %d", preSigners.Size())
	}
	if preSigners.Difference(protocol.Participants()).Size() != 0 {
		return errs.NewMembership("there are some present session participant that are not part of the protocol config")
	}
	if !preSigners.Contains(authKey) {
		return errs.NewMembership("session participants do not include me")
	}
	return nil
}
