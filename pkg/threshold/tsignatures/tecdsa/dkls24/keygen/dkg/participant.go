package dkg

import (
	"fmt"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"

	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	compilerUtils "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler_utils"
	zeroSetup "github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/setup"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/bbot"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

const transcriptLabel = "COPPER_DKLS24_DKG-"

var _ types.ThresholdParticipant = (*Participant)(nil)

type Participant struct {
	types.Participant[types.ThresholdProtocol]

	MyAuthKey             types.AuthKey
	MySharingId           types.SharingID
	MyPartialPublicKeys   *tsignatures.PartialPublicKeys
	ZeroSamplingParty     *zeroSetup.Participant
	BaseOTSenderParties   ds.Map[types.IdentityKey, *bbot.Sender]
	BaseOTReceiverParties ds.Map[types.IdentityKey, *bbot.Receiver]

	_ ds.Incomparable
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.MyAuthKey
}

func (p *Participant) SharingId() types.SharingID {
	return p.MySharingId
}

func NewParticipant(sessionId []byte, authKey types.AuthKey, signingKeyShare *tsignatures.SigningKeyShare, partialPublicKeys *tsignatures.PartialPublicKeys, protocol types.ThresholdProtocol, niCompiler compiler.Name, prng io.Reader, transcript transcripts.Transcript) (*Participant, error) {
	if err := validateInputs(sessionId, authKey, signingKeyShare, partialPublicKeys, protocol, niCompiler, prng); err != nil {
		return nil, errs.WrapArgument(err, "couldn't construct dkls24 dkg participant")
	}

	dst := fmt.Sprintf("%s-%s-%s", transcriptLabel, protocol.Curve().Name(), niCompiler)
	transcript, sessionId, err := hagrid.InitialiseProtocol(transcript, sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, exists := sharingConfig.Reverse().Get(authKey)
	if !exists {
		return nil, errs.NewMissing("could not find my sharing id")
	}

	zeroSamplingParty, err := zeroSetup.NewParticipant(sessionId, authKey, protocol, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not contrust dkls24 dkg participant out of zero samplig setup participant")
	}
	senders := hashmap.NewHashableHashMap[types.IdentityKey, *bbot.Sender]()
	receivers := hashmap.NewHashableHashMap[types.IdentityKey, *bbot.Receiver]()
	for participant := range protocol.Participants().Iter() {
		if participant.Equal(authKey) {
			continue
		}
		otProtocol, err := types.NewMPCProtocol(protocol.Curve(), hashset.NewHashableHashSet(participant, authKey.(types.IdentityKey)))
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct protocol config for myself and %s", participant.String())
		}
		sender, err := bbot.NewSender(authKey, otProtocol, ot.Kappa, 1, sessionId, transcript.Clone(), prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct base ot sender object")
		}
		senders.Put(participant, sender)
		receiver, err := bbot.NewReceiver(authKey, otProtocol, ot.Kappa, 1, sessionId, transcript.Clone(), prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct base ot receiver object")
		}
		receivers.Put(participant, receiver)
	}
	participant := &Participant{
		Participant:           types.NewBaseParticipant(prng, protocol, 1, sessionId, transcript),
		MyAuthKey:             authKey,
		MySharingId:           mySharingId,
		MyPartialPublicKeys:   partialPublicKeys,
		ZeroSamplingParty:     zeroSamplingParty,
		BaseOTSenderParties:   senders,
		BaseOTReceiverParties: receivers,
	}
	if err := types.ValidateThresholdProtocol(participant, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct dkls24 dkg participant")
	}
	return participant, nil
}

func validateInputs(sessionId []byte, authKey types.AuthKey, signingKeyShare *tsignatures.SigningKeyShare, partialPublicKeys *tsignatures.PartialPublicKeys, protocol types.ThresholdProtocol, niCompiler compiler.Name, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewArgument("invalid session id: %s", sessionId)
	}
	if err := types.ValidateThresholdProtocol(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config is invalid")
	}
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "my auth key")
	}
	if !compilerUtils.CompilerIsSupported(niCompiler) {
		return errs.NewType("compiler %s is not supported", niCompiler)
	}
	if err := signingKeyShare.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "private share is invalid")
	}
	if err := partialPublicKeys.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "public share is invalid")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}
