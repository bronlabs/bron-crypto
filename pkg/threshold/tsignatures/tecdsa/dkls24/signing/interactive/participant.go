package interactiveSigning

import (
	"fmt"
	"io"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
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

const transcriptLabel = "COPPER_KRYPTON_TECDSA_DKLS24-"

var _ signing.Participant = (*Cosigner)(nil)

type Cosigner struct {
	prng io.Reader

	myAuthKey   types.AuthKey
	mySharingId types.SharingID
	shard       *dkls24.Shard

	sessionId           []byte
	protocol            types.ThresholdSignatureProtocol
	sharingConfig       types.SharingConfig
	SessionParticipants ds.Set[types.IdentityKey]

	transcript transcripts.Transcript
	state      *signing.SignerState
	round      int

	_ ds.Incomparable
}

func (ic *Cosigner) Shard() *dkls24.Shard {
	return ic.shard
}

func (ic *Cosigner) Protocol() types.ThresholdSignatureProtocol {
	return ic.protocol
}

func (ic *Cosigner) SharingConfig() types.SharingConfig {
	return ic.sharingConfig
}

func (ic *Cosigner) Prng() io.Reader {
	return ic.prng
}

func (ic *Cosigner) SessionId() []byte {
	return ic.sessionId
}

func (ic *Cosigner) IdentityKey() types.IdentityKey {
	return ic.myAuthKey
}

func (ic *Cosigner) SharingId() types.SharingID {
	return ic.mySharingId
}

func (ic *Cosigner) IsSignatureAggregator() bool {
	return ic.Protocol().Participants().Contains(ic.IdentityKey())
}

// NewCosigner constructs the interactive DKLs24 cosigner.
func NewCosigner(sessionId []byte, authKey types.AuthKey, sessionParticipants ds.Set[types.IdentityKey], shard *dkls24.Shard, protocol types.ThresholdSignatureProtocol, prng io.Reader, seededPrng csprng.CSPRNG, transcript transcripts.Transcript) (*Cosigner, error) {
	if err := validateInputs(sessionId, authKey, protocol, shard, sessionParticipants); err != nil {
		return nil, errs.WrapArgument(err, "could not validate input")
	}

	dst := fmt.Sprintf("%s-%s", transcriptLabel, protocol.Curve().Name())
	transcript, sessionId, err := hagrid.InitialiseProtocol(transcript, sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.Reverse().Get(authKey)
	if !exists {
		return nil, errs.NewMissing("could not find my sharing id")
	}

	// step 0.2: zero share sampling setup
	zeroShareSamplingParty, err := sample.NewParticipant(sessionId, authKey, shard.PairwiseSeeds, protocol, sessionParticipants, seededPrng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct zero share sampling party")
	}

	multipliers := hashmap.NewHashableHashMap[types.IdentityKey, *signing.Multiplication]()
	for participant := range sessionParticipants.Iter() {
		if participant.Equal(authKey) {
			continue
		}
		seedOtResults, exists := shard.PairwiseBaseOTs.Get(participant)
		if !exists {
			return nil, errs.NewMissing("missing ot config for participant %x", participant.PublicKey())
		}
		// step 0.3: RVOLE setup as Alice, with P_k as Bob
		alice, err := mult.NewAlice(protocol.Curve(), seedOtResults.AsReceiver, sessionId, prng, seededPrng, transcript.Clone())
		if err != nil {
			return nil, errs.WrapFailed(err, "alice construction for participant %x", participant.PublicKey().ToAffineCompressed())
		}
		// step 0.4: RVOLE setup as Bob, with P_k as Alice
		bob, err := mult.NewBob(protocol.Curve(), seedOtResults.AsSender, sessionId, prng, seededPrng, transcript.Clone())
		if err != nil {
			return nil, errs.WrapFailed(err, "bob construction for participant %x", participant.PublicKey().ToAffineCompressed())
		}
		multipliers.Put(participant, &signing.Multiplication{
			Alice: alice,
			Bob:   bob,
		})
	}

	cosigner := &Cosigner{
		myAuthKey:           authKey,
		protocol:            protocol,
		shard:               shard,
		sessionId:           sessionId,
		SessionParticipants: sessionParticipants,
		prng:                prng,
		transcript:          transcript,
		state: &signing.SignerState{
			Protocols: &signing.SubProtocols{
				ZeroShareSampling: zeroShareSamplingParty,
				Multiplication:    multipliers,
			},
		},
		mySharingId:   mySharingId,
		sharingConfig: sharingConfig,
		round:         1,
	}

	if err := types.ValidateThresholdSignatureProtocol(cosigner, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct a valid interactive dkls24 cosigner")
	}

	return cosigner, nil
}

func validateInputs(sessionId []byte, authKey types.AuthKey, protocol types.ThresholdSignatureProtocol, shard *dkls24.Shard, sessionParticipants ds.Set[types.IdentityKey]) error {
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
	if sessionParticipants == nil {
		return errs.NewIsNil("invalid number of session participants")
	}
	if sessionParticipants.Size() < int(protocol.Threshold()) {
		return errs.NewSize("not enough session participants: %d", sessionParticipants.Size())
	}
	if sessionParticipants.Difference(protocol.Participants()).Size() != 0 {
		return errs.NewMembership("there are some present session participant that are not part of the protocol config")
	}
	if !sessionParticipants.Contains(authKey) {
		return errs.NewMembership("session participants do not include me")
	}
	return nil
}
