package interactive

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

const transcriptLabel = "COPPER_KRYPTON_TECDSA_DKLS24-"

type Cosigner struct {
	*signing.Participant

	Quorum ds.Set[types.IdentityKey]

	state *signing.SignerState

	_ ds.Incomparable
}

func (ic *Cosigner) IsSignatureAggregator() bool {
	return ic.Protocol.Participants().Contains(ic.IdentityKey())
}

// NewCosigner constructs the interactive DKLs24 cosigner.
func NewCosigner(sessionId []byte, authKey types.AuthKey, quorum ds.Set[types.IdentityKey], shard *dkls23.Shard, protocol types.ThresholdSignatureProtocol, prng io.Reader, seededPrng csprng.CSPRNG, transcript transcripts.Transcript) (*Cosigner, error) {
	if err := validateInputs(sessionId, authKey, protocol, shard, quorum); err != nil {
		return nil, errs.WrapArgument(err, "could not validate input")
	}

	dst := fmt.Sprintf("%s-%s", transcriptLabel, protocol.Curve().Name())
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, nil)
	}
	boundSessionId, err := transcript.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.Reverse().Get(authKey)
	if !exists {
		return nil, errs.NewMissing("could not find my sharing id")
	}

	// step 0.2: zero share sampling setup
	zeroShareSamplingParty, err := sample.NewParticipant(boundSessionId, authKey, shard.PairwiseSeeds, protocol, quorum, seededPrng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct zero share sampling party")
	}

	multipliers := hashmap.NewHashableHashMap[types.IdentityKey, *signing.Multiplication]()
	for iterator := quorum.Iterator(); iterator.HasNext(); {
		participant := iterator.Next()
		if participant.Equal(authKey) {
			continue
		}
		seedOtResults, exists := shard.PairwiseBaseOTs.Get(participant)
		if !exists {
			return nil, errs.NewMissing("missing ot config for participant %s", participant.String())
		}
		otProtocol, err := types.NewProtocol(protocol.Curve(), hashset.NewHashableHashSet(participant, authKey.(types.IdentityKey)))
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct ot protocol config for me and %s", participant.String())
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
		// step 0.3: RVOLE setup as Alice, with P_k as Bob
		alice, err := mult.NewAlice(authKey, otProtocol, seedOtResults.AsReceiver, multSessionId, prng, seededPrng, multTranscript.Clone())
		if err != nil {
			return nil, errs.WrapFailed(err, "alice construction for participant %s", participant.String())
		}
		// step 0.4: RVOLE setup as Bob, with P_k as Alice
		bob, err := mult.NewBob(authKey, otProtocol, seedOtResults.AsSender, multSessionId, prng, seededPrng, multTranscript.Clone())
		if err != nil {
			return nil, errs.WrapFailed(err, "bob construction for participant %s", participant.String())
		}
		multipliers.Put(participant, &signing.Multiplication{
			Alice: alice,
			Bob:   bob,
		})
	}
	signingParticipant := signing.NewParticipant(authKey, prng, protocol, boundSessionId, transcript, mySharingId, sharingConfig, shard)
	cosigner := &Cosigner{
		Participant: signingParticipant,
		Quorum:      quorum,
		state: &signing.SignerState{
			Protocols: &signing.SubProtocols{
				ZeroShareSampling: zeroShareSamplingParty,
				Multiplication:    multipliers,
			},
		},
	}
	if err := types.ValidateThresholdSignatureProtocol(cosigner, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct a valid interactive dkls24 cosigner")
	}
	return cosigner, nil
}

func validateInputs(sessionId []byte, authKey types.AuthKey, protocol types.ThresholdSignatureProtocol, shard *dkls23.Shard, quorum ds.Set[types.IdentityKey]) error {
	if len(sessionId) == 0 {
		return errs.NewLength("invalid session id: %s", sessionId)
	}
	if err := types.ValidateThresholdSignatureProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "threshold signature protocol config")
	}
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if err := shard.Validate(protocol, authKey); err != nil {
		return errs.WrapValidation(err, "could not validate shard")
	}
	if quorum == nil {
		return errs.NewIsNil("invalid number of session participants")
	}
	if quorum.Size() < int(protocol.Threshold()) {
		return errs.NewSize("not enough session participants: %d", quorum.Size())
	}
	if quorum.Difference(protocol.Participants()).Size() != 0 {
		return errs.NewMembership("there are some present session participant that are not part of the protocol config")
	}
	if !quorum.Contains(authKey) {
		return errs.NewMembership("session participants do not include me")
	}
	return nil
}
