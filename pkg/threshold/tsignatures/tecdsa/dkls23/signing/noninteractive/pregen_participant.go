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
	mult "github.com/copperexchange/krypton-primitives/pkg/threshold/mult/dkls23"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/rprzs/sample"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23/signing"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const transcriptLabel = "COPPER_KRYPTON_PREGEN_DKLS23-"

var _ types.ThresholdParticipant = (*PreGenParticipant)(nil) // only threshold piece of the protocol is important.

type PreGenParticipant struct {
	signing.Participant

	Quorum ds.Set[types.IdentityKey]

	state *signing.SignerState

	_ ds.Incomparable
}

func NewPreGenParticipant(sessionId []byte, myAuthKey types.AuthKey, preSigners ds.Set[types.IdentityKey], myShard *dkls23.Shard, protocol types.ThresholdSignatureProtocol, transcript transcripts.Transcript, prng io.Reader, seededPrng csprng.CSPRNG) (participant *PreGenParticipant, err error) {
	if err := validateInputs(sessionId, myAuthKey, protocol, myShard, preSigners); err != nil {
		return nil, errs.WrapArgument(err, "could not validate input")
	}

	dst := fmt.Sprintf("%s-%s", transcriptLabel, protocol.Curve().Name())
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, prng)
	}
	boundSessionId, err := transcript.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.Reverse().Get(myAuthKey)
	if !exists {
		return nil, errs.NewMissing("could not find my sharing id")
	}

	// step 0.2
	zeroShareSamplingParty, err := sample.NewParticipant(boundSessionId, myAuthKey, myShard.PairwiseSeeds, protocol, preSigners, seededPrng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct zero share sampling party")
	}

	// step 0.3
	multipliers := hashmap.NewHashableHashMap[types.IdentityKey, *signing.Multiplication]()
	for participant := range preSigners.Iter() {
		if participant.Equal(myAuthKey) {
			continue
		}
		otProtocol, err := types.NewProtocol(protocol.Curve(), hashset.NewHashableHashSet(participant, myAuthKey.(types.IdentityKey)))
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct ot protocol config for me and %s", participant.String())
		}
		seedOtResults, exists := myShard.PairwiseBaseOTs.Get(participant)
		if !exists {
			return nil, errs.NewMissing("missing ot config for participant %s", participant.String())
		}
		multTranscript := transcript.Clone()
		identities := types.NewIdentitySpace(otProtocol.Participants())
		first, exists := identities.Get(1)
		if !exists {
			return nil, errs.NewMissing("could not find the first multiplier's identity")
		}
		second, exists := identities.Get(2)
		if !exists {
			return nil, errs.NewMissing("could not find the second multiplier's identity")
		}
		multTranscript.AppendMessages("participants", first.PublicKey().ToAffineCompressed(), second.PublicKey().ToAffineCompressed())
		multSessionId, err := multTranscript.Bind(boundSessionId, dst)
		if err != nil {
			return nil, errs.WrapHashing(err, "could not produce binded session id for mult")
		}
		alice, err := mult.NewAlice(myAuthKey, otProtocol, seedOtResults.AsReceiver, multSessionId, prng, seededPrng, multTranscript.Clone())
		if err != nil {
			return nil, errs.WrapFailed(err, "alice construction for participant %s", participant.String())
		}
		bob, err := mult.NewBob(myAuthKey, otProtocol, seedOtResults.AsSender, multSessionId, prng, seededPrng, multTranscript.Clone())
		if err != nil {
			return nil, errs.WrapFailed(err, "bob construction for participant %s", participant.String())
		}
		multipliers.Put(participant, &signing.Multiplication{
			Alice: alice,
			Bob:   bob,
		})
	}

	signingParticipant := signing.NewParticipant(myAuthKey, prng, protocol, boundSessionId, transcript, mySharingId, sharingConfig, myShard)
	participant = &PreGenParticipant{
		Participant: *signingParticipant,
		state: &signing.SignerState{
			Protocols: &signing.SubProtocols{
				ZeroShareSampling: zeroShareSamplingParty,
				Multiplication:    multipliers,
			},
		},
		Quorum: preSigners,
	}

	if err := types.ValidateThresholdProtocol(participant, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct a lindell22 pregen participant")
	}

	return participant, nil
}

func validateInputs(sessionId []byte, authKey types.AuthKey, protocol types.ThresholdProtocol, shard *dkls23.Shard, preSigners ds.Set[types.IdentityKey]) error {
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
