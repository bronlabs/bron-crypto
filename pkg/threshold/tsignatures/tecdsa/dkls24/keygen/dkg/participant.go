package dkg

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	compilerUtils "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler_utils"
	zeroSetup "github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/setup"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/bbot"
	"github.com/copperexchange/krypton-primitives/pkg/ot/extension/softspoken"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/gennaro"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

const DkgLabel = "COPPER_DKLS24_DKG-"

var _ types.ThresholdParticipant = (*Participant)(nil)

type Participant struct {
	MyAuthKey             types.AuthKey
	GennaroParty          *gennaro.Participant
	ZeroSamplingParty     *zeroSetup.Participant
	BaseOTSenderParties   ds.HashMap[types.IdentityKey, *bbot.Sender]
	BaseOTReceiverParties ds.HashMap[types.IdentityKey, *bbot.Receiver]
	Protocol              types.ThresholdProtocol

	Shard *dkls24.Shard

	_ ds.Incomparable
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.GennaroParty.IdentityKey()
}

func (p *Participant) SharingId() types.SharingID {
	return p.GennaroParty.SharingId()
}

func NewParticipant(uniqueSessionId []byte, authKey types.AuthKey, protocol types.ThresholdProtocol, niCompiler compiler.Name, prng io.Reader, transcript transcripts.Transcript) (*Participant, error) {
	if err := validateInputs(uniqueSessionId, authKey, protocol, niCompiler, prng); err != nil {
		return nil, errs.WrapArgument(err, "couldn't construct dkls24 dkg participant")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript(DkgLabel, prng)
	}
	transcript.AppendMessages("DKLs24 DKG Participant", uniqueSessionId)
	gennaroParty, err := gennaro.NewParticipant(uniqueSessionId, authKey, protocol, niCompiler, prng, transcript)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct dkls24 dkg participant out of gennaro dkg participant")
	}
	zeroSamplingParty, err := zeroSetup.NewParticipant(uniqueSessionId, authKey, protocol, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not contrust dkls24 dkg participant out of zero samplig setup participant")
	}
	senders := hashmap.NewHashableHashMap[types.IdentityKey, *bbot.Sender]()
	receivers := hashmap.NewHashableHashMap[types.IdentityKey, *bbot.Receiver]()
	for participant := range protocol.Participants().Iter() {
		if participant.Equal(authKey) {
			continue
		}
		sender, err := bbot.NewSender(softspoken.Kappa, 1, protocol.Curve(), uniqueSessionId, transcript.Clone(), prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct base ot sender object")
		}
		senders.Put(participant, sender)
		receiver, err := bbot.NewReceiver(softspoken.Kappa, 1, protocol.Curve(), uniqueSessionId, transcript.Clone(), prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct base ot receiver object")
		}
		receivers.Put(participant, receiver)
	}
	participant := &Participant{
		MyAuthKey:             authKey,
		GennaroParty:          gennaroParty,
		ZeroSamplingParty:     zeroSamplingParty,
		BaseOTSenderParties:   senders,
		BaseOTReceiverParties: receivers,
		Shard:                 &dkls24.Shard{},
		Protocol:              protocol,
	}
	if err := types.ValidateThresholdProtocol(participant, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct dkls24 dkg participant")
	}
	return participant, nil
}

func validateInputs(sessionId []byte, authKey types.AuthKey, protocol types.ThresholdProtocol, niCompiler compiler.Name, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewArgument("invalid session id: %s", sessionId)
	}
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config is invalid")
	}
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "my auth key")
	}
	if !compilerUtils.CompilerIsSupported(niCompiler) {
		return errs.NewType("compiler %s is not supported", niCompiler)
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}
