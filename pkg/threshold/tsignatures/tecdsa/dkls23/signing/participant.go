package signing

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	hashcommitments "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/csprng"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/bbot"
	mult "github.com/bronlabs/bron-crypto/pkg/threshold/mult/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/rprzs"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/rprzs/sample"
	zeroSetup "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/rprzs/setup"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

var _ types.ThresholdSignatureParticipant = (*Participant)(nil)

const transcriptLabel = "KRYPTON_DKLS23_-"

type Participant struct {
	// Base participant
	myAuthKey  types.AuthKey
	Prng       io.Reader
	SeededPrng csprng.CSPRNG
	Protocol   types.ThresholdSignatureProtocol
	Round      int
	SessionId  []byte
	Transcript transcripts.Transcript

	// Threshold participant
	mySharingId   types.SharingID
	sharingConfig types.SharingConfig

	shard  *dkls23.Shard
	quorum ds.Set[types.IdentityKey]

	// Run bbot during signing
	SubProtocols          *SubProtocols
	ZeroSamplingParty     *zeroSetup.Participant
	BaseOTSenderParties   ds.Map[types.IdentityKey, *bbot.Sender]
	BaseOTReceiverParties ds.Map[types.IdentityKey, *bbot.Receiver]
}

func (p *Participant) AuthKey() types.AuthKey {
	return p.myAuthKey
}

func (p *Participant) InitializeZeroShareSamplingParty(pairwiseSeeds rprzs.PairWiseSeeds) error {
	// step 0.2: zero share sampling setup
	zeroShareSamplingParty, err := sample.NewParticipant(p.SessionId, p.AuthKey(), pairwiseSeeds, p.Protocol, p.Quorum(), p.SeededPrng)
	if err != nil {
		return errs.WrapFailed(err, "could not construct zero share sampling party")
	}
	p.SubProtocols.ZeroShareSampling = zeroShareSamplingParty
	return nil
}

func (p *Participant) InitializeMultipliers(pairwiseBaseOTs ds.Map[types.IdentityKey, *BaseOTConfig]) error {
	multipliers := hashmap.NewHashableHashMap[types.IdentityKey, *Multiplication]()
	for participant := range p.Quorum().Iter() {
		if participant.Equal(p.IdentityKey()) {
			continue
		}
		seedOtResults, exists := pairwiseBaseOTs.Get(participant)
		if !exists {
			return errs.NewMissing("missing ot config for participant %s", participant.String())
		}

		otProtocol, err := types.NewProtocol(p.Protocol.Curve(), hashset.NewHashableHashSet(participant, p.IdentityKey()))
		if err != nil {
			return errs.WrapFailed(err, "could not construct ot protocol config for me and %s", participant.String())
		}

		multTranscript := p.Transcript.Clone()
		identities := types.NewIdentitySpace(otProtocol.Participants())
		first, exists := identities.Get(1)
		if !exists {
			return errs.NewMissing("could not find the first multiplier's identity")
		}
		second, exists := identities.Get(2)
		if !exists {
			return errs.NewMissing("could not find the second multiplier's identity")
		}
		multTranscript.AppendMessages("participants", first.PublicKey().ToAffineCompressed(), second.PublicKey().ToAffineCompressed())
		dst := fmt.Sprintf("initialise multiplication between %s and %s", first.String(), second.String())
		multSessionId, err := multTranscript.Bind(p.SessionId, dst)
		if err != nil {
			return errs.WrapHashing(err, "could not produce binded session id for mult")
		}
		// step 0.3: RVOLE setup as Alice, with P_k as Bob
		alice, err := mult.NewAlice(p.AuthKey(), otProtocol, seedOtResults.AsReceiver, multSessionId, p.Prng, p.SeededPrng, multTranscript.Clone())
		if err != nil {
			return errs.WrapFailed(err, "alice construction for participant %s", participant.String())
		}
		// step 0.4: RVOLE setup as Bob, with P_k as Alice
		bob, err := mult.NewBob(p.AuthKey(), otProtocol, seedOtResults.AsSender, multSessionId, p.Prng, p.SeededPrng, multTranscript.Clone())
		if err != nil {
			return errs.WrapFailed(err, "bob construction for participant %s", participant.String())
		}
		multipliers.Put(participant, &Multiplication{
			Alice: alice,
			Bob:   bob,
		})
	}
	p.SubProtocols.Multiplication = multipliers
	return nil
}

func NewParticipant(
	myAuthKey types.AuthKey,
	prng io.Reader,
	protocol types.ThresholdSignatureProtocol,
	sessionId []byte,
	transcript transcripts.Transcript,
	quorum ds.Set[types.IdentityKey],
	shard *dkls23.Shard,
) (*Participant, error) {
	if err := validateInputs(sessionId, myAuthKey, protocol, quorum, shard, prng); err != nil {
		return nil, errs.WrapArgument(err, "couldn't construct dkls23 dkg participant")
	}

	sharingConfig := types.DeriveSharingConfig(quorum)
	mySharingId, ok := sharingConfig.Reverse().Get(myAuthKey)
	if !ok {
		return nil, errs.NewMissing("myAuthKey not found in quorum")
	}

	dst := fmt.Sprintf("%s-%s", transcriptLabel, protocol.Curve().Name())
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, prng)
	}
	boundSessionId, err := transcript.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	zeroSamplingProtocol, err := types.NewProtocol(protocol.Curve(), quorum)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct zero sampling protocol")
	}
	zeroSamplingParty, err := zeroSetup.NewParticipant(boundSessionId, myAuthKey, zeroSamplingProtocol, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not contrust dkls23 dkg participant out of zero samplig setup participant")
	}
	senders := hashmap.NewHashableHashMap[types.IdentityKey, *bbot.Sender]()
	receivers := hashmap.NewHashableHashMap[types.IdentityKey, *bbot.Receiver]()
	for participant := range quorum.Iter() {
		if participant.Equal(myAuthKey) {
			continue
		}
		otProtocol, err := types.NewProtocol(protocol.Curve(), hashset.NewHashableHashSet(participant, myAuthKey.(types.IdentityKey))) //nolint:errcheck // trivial type check
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct protocol config for myself and %s", participant.String())
		}
		sender, err := bbot.NewSender(myAuthKey, otProtocol, ot.Kappa, 1, boundSessionId, transcript.Clone(), prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct base ot sender object")
		}
		senders.Put(participant, sender)
		receiver, err := bbot.NewReceiver(myAuthKey, otProtocol, ot.Kappa, 1, boundSessionId, transcript.Clone(), prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct base ot receiver object")
		}
		receivers.Put(participant, receiver)
	}

	participant := &Participant{
		myAuthKey:             myAuthKey,
		Prng:                  prng,
		Protocol:              protocol,
		Round:                 1,
		SessionId:             sessionId,
		Transcript:            transcript,
		mySharingId:           mySharingId,
		sharingConfig:         sharingConfig,
		shard:                 shard,
		quorum:                quorum,
		ZeroSamplingParty:     zeroSamplingParty,
		BaseOTSenderParties:   senders,
		BaseOTReceiverParties: receivers,
		SubProtocols:          &SubProtocols{},
	}

	if err := types.ValidateThresholdSignatureProtocol(participant, protocol); err != nil {
		return nil, errs.WrapValidation(err, "participant")
	}

	return participant, nil
}

func validateInputs(sessionId []byte, myAuthKey types.AuthKey, protocol types.ThresholdSignatureProtocol, quorum ds.Set[types.IdentityKey], shard *dkls23.Shard, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewArgument("invalid session id: %s", sessionId)
	}
	if err := types.ValidateThresholdSignatureProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config is invalid")
	}
	if err := types.ValidateAuthKey(myAuthKey); err != nil {
		return errs.WrapValidation(err, "my auth key")
	}
	if err := shard.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "shard")
	}
	if quorum == nil {
		return errs.NewIsNil("quorum is nil")
	}
	if !protocol.Participants().IsSuperSet(quorum) {
		return errs.NewMembership("quorum is not subset of all participants")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.myAuthKey
}

func (p *Participant) SharingId() types.SharingID {
	return p.mySharingId
}

func (p *Participant) Shard() *dkls23.Shard {
	return p.shard
}

func (p *Participant) Quorum() ds.Set[types.IdentityKey] {
	return p.quorum
}

func (p *Participant) SharingConfig() types.SharingConfig {
	return p.sharingConfig
}

func (p *Participant) IsSignatureAggregator() bool {
	return p.Protocol.Participants().Contains(p.IdentityKey())
}

// Multiplication contains corresponding participant objects for pairwise multiplication subProtocols.
type Multiplication struct {
	Alice *mult.Alice
	Bob   *mult.Bob

	_ ds.Incomparable
}

type SubProtocols struct {
	// use to get the secret key mask (zeta_i)
	ZeroShareSampling *sample.Participant
	// pairwise multiplication protocol i.e. each party acts as alice and bob against every party
	Multiplication ds.Map[types.IdentityKey, *Multiplication]

	_ ds.Incomparable
}

type BaseOTConfig struct {
	AsSender   *ot.SenderRotOutput
	AsReceiver *ot.ReceiverRotOutput

	_ ds.Incomparable
}

func (b *BaseOTConfig) Validate() error {
	if b.AsSender == nil || len(b.AsSender.MessagePairs) == 0 {
		return errs.NewArgument("invalid base OT as sender")
	}
	if b.AsReceiver == nil || len(b.AsReceiver.ChosenMessages) == 0 || len(b.AsReceiver.Choices) == 0 {
		return errs.NewArgument("invalid base OT as receiver")
	}
	return nil
}

type SignerState struct {
	Phi_i                          curves.Scalar
	Sk_i                           curves.Scalar
	R_i                            curves.Scalar
	Zeta_i                         curves.Scalar
	BigR_i                         curves.Point
	Pk_i                           curves.Point
	Cu_i                           map[types.SharingID]curves.Scalar
	Cv_i                           map[types.SharingID]curves.Scalar
	Du_i                           map[types.SharingID]curves.Scalar
	Dv_i                           map[types.SharingID]curves.Scalar
	Psi_i                          map[types.SharingID]curves.Scalar
	Chi_i                          map[types.SharingID]curves.Scalar
	InstanceKeyOpening             map[types.SharingID]hashcommitments.Witness
	ReceivedInstanceKeyCommitments map[types.SharingID]hashcommitments.Commitment
	ReceivedBigR_i                 ds.Map[types.IdentityKey, curves.Point]

	PairwiseSeeds   rprzs.PairWiseSeeds
	PairwiseBaseOTs ds.Map[types.IdentityKey, *BaseOTConfig]

	_ ds.Incomparable
}
