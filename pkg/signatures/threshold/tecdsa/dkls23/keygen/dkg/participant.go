package dkg

import (
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/dkg/gennaro"
	"github.com/copperexchange/knox-primitives/pkg/ot/base/vsot"
	zeroSetup "github.com/copperexchange/knox-primitives/pkg/sharing/zero/setup"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"

	"github.com/copperexchange/knox-primitives/pkg/core/integration"
)

const DkgLabel = "COPPER_DKLS23_DKG-"

type Participant struct {
	MyIdentityKey         integration.IdentityKey
	GennaroParty          *gennaro.Participant
	ZeroSamplingParty     *zeroSetup.Participant
	BaseOTSenderParties   map[helper_types.IdentityHash]*vsot.Sender
	BaseOTReceiverParties map[helper_types.IdentityHash]*vsot.Receiver

	Shard *dkls23.Shard

	_ helper_types.Incomparable
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
	if transcript == nil {
		transcript = hagrid.NewTranscript(DkgLabel)
	}
	gennaroParty, err := gennaro.NewParticipant(uniqueSessionId, identityKey, cohortConfig, prng, transcript)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct dkls23 dkg participant out of gennaro dkg participant")
	}
	zeroSamplingParty, err := zeroSetup.NewParticipant(cohortConfig.CipherSuite.Curve, uniqueSessionId, identityKey, cohortConfig.Participants, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not contrust dkls23 dkg participant out of zero samplig setup participant")
	}
	senders := make(map[helper_types.IdentityHash]*vsot.Sender, len(cohortConfig.Participants)-1)
	receivers := make(map[helper_types.IdentityHash]*vsot.Receiver, len(cohortConfig.Participants)-1)
	for _, participant := range cohortConfig.Participants {
		if participant.PublicKey().Equal(identityKey.PublicKey()) {
			continue
		}
		// 256 should be replaced with kappa once ot extensions are here
		senders[participant.Hash()], err = vsot.NewSender(cohortConfig.CipherSuite.Curve, 256, uniqueSessionId, transcript, prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct base ot sender object")
		}
		receivers[participant.Hash()], err = vsot.NewReceiver(cohortConfig.CipherSuite.Curve, 256, uniqueSessionId, transcript, prng)
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
