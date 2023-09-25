package dkg

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot"
	"github.com/copperexchange/krypton-primitives/pkg/ot/extension/softspoken"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/gennaro"
	zeroSetup "github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/setup"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const DkgLabel = "COPPER_DKLS23_DKG-"

type Participant struct {
	MyIdentityKey         integration.IdentityKey
	GennaroParty          *gennaro.Participant
	ZeroSamplingParty     *zeroSetup.Participant
	BaseOTSenderParties   map[types.IdentityHash]*vsot.Sender
	BaseOTReceiverParties map[types.IdentityHash]*vsot.Receiver

	Shard *dkls23.Shard

	_ types.Incomparable
}

func (p *Participant) GetIdentityKey() integration.IdentityKey {
	return p.GennaroParty.GetIdentityKey()
}

func (p *Participant) GetSharingId() int {
	return p.GennaroParty.GetSharingId()
}

func (p *Participant) GetCohortConfig() *integration.CohortConfig {
	return p.GennaroParty.GetCohortConfig()
}

func NewParticipant(uniqueSessionId []byte, identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, prng io.Reader, transcript transcripts.Transcript) (*Participant, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapInvalidArgument(err, "cohort config is invalid")
	}
	if len(uniqueSessionId) == 0 {
		return nil, errs.NewInvalidArgument("unique session id is empty")
	}
	if identityKey == nil {
		return nil, errs.NewInvalidArgument("identityKey key is nil")
	}
	if prng == nil {
		return nil, errs.NewInvalidArgument("prng is nil")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript(DkgLabel, nil)
	}
	gennaroParty, err := gennaro.NewParticipant(uniqueSessionId, identityKey, cohortConfig, prng, transcript)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct dkls23 dkg participant out of gennaro dkg participant")
	}
	zeroSamplingParty, err := zeroSetup.NewParticipant(cohortConfig.CipherSuite.Curve, uniqueSessionId, identityKey, cohortConfig.Participants, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not contrust dkls23 dkg participant out of zero samplig setup participant")
	}
	senders := make(map[types.IdentityHash]*vsot.Sender, cohortConfig.Participants.Len()-1)
	receivers := make(map[types.IdentityHash]*vsot.Receiver, cohortConfig.Participants.Len()-1)
	for _, participant := range cohortConfig.Participants.Iter() {
		if participant.PublicKey().Equal(identityKey.PublicKey()) {
			continue
		}
		senders[participant.Hash()], err = vsot.NewSender(cohortConfig.CipherSuite.Curve, softspoken.Kappa, uniqueSessionId, transcript, prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct base ot sender object")
		}
		receivers[participant.Hash()], err = vsot.NewReceiver(cohortConfig.CipherSuite.Curve, softspoken.Kappa, uniqueSessionId, transcript, prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct base ot receiver object")
		}
	}
	transcript.AppendMessages("DKLs23 DKG Participant", uniqueSessionId)
	return &Participant{
		MyIdentityKey:         identityKey,
		GennaroParty:          gennaroParty,
		ZeroSamplingParty:     zeroSamplingParty,
		BaseOTSenderParties:   senders,
		BaseOTReceiverParties: receivers,
		Shard:                 &dkls23.Shard{},
	}, nil
}
