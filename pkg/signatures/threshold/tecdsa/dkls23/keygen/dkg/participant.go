package dkg

import (
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/dkg/gennaro"
	"github.com/copperexchange/crypto-primitives-go/pkg/ot/base/vsot"
	zeroSetup "github.com/copperexchange/crypto-primitives-go/pkg/sharing/zero/setup"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/dkls23"
	"github.com/copperexchange/crypto-primitives-go/pkg/transcript"
	"github.com/copperexchange/crypto-primitives-go/pkg/transcript/merlin"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
)

const DkgLabel = "COPPER_DKLS23_DKG-"

type Participant struct {
	MyIdentityKey         integration.IdentityKey
	GennaroParty          *gennaro.Participant
	ZeroSamplingParty     *zeroSetup.Participant
	BaseOTSenderParties   map[integration.IdentityKey]*vsot.Sender
	BaseOTReceiverParties map[integration.IdentityKey]*vsot.Receiver

	Shard *dkls23.Shard
}

func (p *Participant) GetIdentityKey() integration.IdentityKey {
	return p.GennaroParty.GetIdentityKey()
}

func (p *Participant) GetShamirId() int {
	return p.GennaroParty.GetShamirId()
}

func (p *Participant) GetCohortConfig() *integration.CohortConfig {
	return p.GennaroParty.GetCohortConfig()
}

func NewParticipant(uniqueSessionId []byte, identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, prng io.Reader, transcript transcript.Transcript) (*Participant, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapInvalidArgument(err, "cohort config is invalid")
	}
	if transcript == nil {
		transcript = merlin.NewTranscript(DkgLabel)
	}
	gennaroParty, err := gennaro.NewParticipant(uniqueSessionId, identityKey, cohortConfig, prng, transcript)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct dkls23 dkg participant out of gennaro dkg participant")
	}
	zeroSamplingParty, err := zeroSetup.NewParticipant(cohortConfig.CipherSuite.Curve, uniqueSessionId, identityKey, cohortConfig.Participants, transcript, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not contrust dkls23 dkg participant out of zero samplig setup participant")
	}
	senders := make(map[integration.IdentityKey]*vsot.Sender, len(cohortConfig.Participants)-1)
	receivers := make(map[integration.IdentityKey]*vsot.Receiver, len(cohortConfig.Participants)-1)
	for _, participant := range cohortConfig.Participants {
		if participant.PublicKey().Equal(identityKey.PublicKey()) {
			continue
		}
		// 256 should be replaced with kappa once ot extensions are here
		senders[participant], err = vsot.NewSender(cohortConfig.CipherSuite.Curve, 256, uniqueSessionId, transcript)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct base ot sender object")
		}
		receivers[participant], err = vsot.NewReceiver(cohortConfig.CipherSuite.Curve, 256, uniqueSessionId, transcript)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct base ot receiver object")
		}
	}
	transcript.AppendMessage([]byte("DKLs23 DKG Participant"), uniqueSessionId)
	return &Participant{
		MyIdentityKey:         identityKey,
		GennaroParty:          gennaroParty,
		ZeroSamplingParty:     zeroSamplingParty,
		BaseOTSenderParties:   senders,
		BaseOTReceiverParties: receivers,
		Shard:                 &dkls23.Shard{},
	}, nil
}
