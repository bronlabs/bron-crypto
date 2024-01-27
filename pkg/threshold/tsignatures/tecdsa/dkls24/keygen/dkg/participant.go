package dkg

import (
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randomised_fischlin"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/bbot"
	"github.com/copperexchange/krypton-primitives/pkg/ot/extension/softspoken"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/gennaro"
	zeroSetup "github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/setup"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const DkgLabel = "COPPER_DKLS24_DKG-"

type Participant struct {
	MyAuthKey             integration.AuthKey
	GennaroParty          *gennaro.Participant
	ZeroSamplingParty     *zeroSetup.Participant
	BaseOTSenderParties   map[types.IdentityHash]*bbot.Sender
	BaseOTReceiverParties map[types.IdentityHash]*bbot.Receiver

	Shard *dkls24.Shard

	_ types.Incomparable
}

func (p *Participant) GetAuthKey() integration.AuthKey {
	return p.GennaroParty.GetAuthKey()
}

func (p *Participant) GetSharingId() int {
	return p.GennaroParty.GetSharingId()
}

func (p *Participant) GetCohortConfig() *integration.CohortConfig {
	return p.GennaroParty.GetCohortConfig()
}

func NewParticipant(uniqueSessionId []byte, authKey integration.AuthKey, cohortConfig *integration.CohortConfig, prng io.Reader, transcript transcripts.Transcript) (*Participant, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapInvalidArgument(err, "cohort config is invalid")
	}
	if len(uniqueSessionId) == 0 {
		return nil, errs.NewInvalidArgument("unique session id is empty")
	}
	if authKey == nil {
		return nil, errs.NewInvalidArgument("identityKey key is nil")
	}
	if prng == nil {
		return nil, errs.NewInvalidArgument("prng is nil")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript(DkgLabel, nil)
	}
	gennaroParty, err := gennaro.NewParticipant(uniqueSessionId, authKey, cohortConfig, randomisedFischlin.Name, prng, transcript)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct dkls24 dkg participant out of gennaro dkg participant")
	}
	zeroSamplingParty, err := zeroSetup.NewParticipant(cohortConfig.CipherSuite.Curve, uniqueSessionId, authKey, cohortConfig.Participants, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not contrust dkls24 dkg participant out of zero samplig setup participant")
	}
	senders := make(map[types.IdentityHash]*bbot.Sender, cohortConfig.Participants.Len()-1)
	receivers := make(map[types.IdentityHash]*bbot.Receiver, cohortConfig.Participants.Len()-1)
	for _, participant := range cohortConfig.Participants.Iter() {
		if participant.PublicKey().Equal(authKey.PublicKey()) {
			continue
		}
		senders[participant.Hash()], err = bbot.NewSender(softspoken.Kappa, 1, cohortConfig.CipherSuite.Curve, uniqueSessionId, transcript.Clone(), prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct base ot sender object")
		}
		receivers[participant.Hash()], err = bbot.NewReceiver(softspoken.Kappa, 1, cohortConfig.CipherSuite.Curve, uniqueSessionId, transcript.Clone(), prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct base ot receiver object")
		}
	}
	transcript.AppendMessages("DKLs24 DKG Participant", uniqueSessionId)
	return &Participant{
		MyAuthKey:             authKey,
		GennaroParty:          gennaroParty,
		ZeroSamplingParty:     zeroSamplingParty,
		BaseOTSenderParties:   senders,
		BaseOTReceiverParties: receivers,
		Shard:                 &dkls24.Shard{},
	}, nil
}
