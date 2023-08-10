package dkg

import (
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashmap"
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/dkg/gennaro"
	"github.com/copperexchange/knox-primitives/pkg/ot/base/vsot"
	zeroSetup "github.com/copperexchange/knox-primitives/pkg/sharing/zero/setup"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/merlin"

	"github.com/copperexchange/knox-primitives/pkg/core/integration"
)

const DkgLabel = "COPPER_DKLS23_DKG-"

type Participant struct {
	MyIdentityKey         integration.IdentityKey
	GennaroParty          *gennaro.Participant
	ZeroSamplingParty     *zeroSetup.Participant
	BaseOTSenderParties   *hashmap.HashMap[integration.IdentityKey, *vsot.Sender]
	BaseOTReceiverParties *hashmap.HashMap[integration.IdentityKey, *vsot.Receiver]

	Shard *dkls23.Shard
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
	senders := hashmap.NewHashMap[integration.IdentityKey, *vsot.Sender]()
	receivers := hashmap.NewHashMap[integration.IdentityKey, *vsot.Receiver]()
	for _, participant := range cohortConfig.Participants {
		if participant.PublicKey().Equal(identityKey.PublicKey()) {
			continue
		}
		// 256 should be replaced with kappa once ot extensions are here
		newSender, err := vsot.NewSender(cohortConfig.CipherSuite.Curve, 256, uniqueSessionId, transcript)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct base ot sender object")
		}
		senders.Put(participant, newSender)
		newReceiver, err := vsot.NewReceiver(cohortConfig.CipherSuite.Curve, 256, uniqueSessionId, transcript)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct base ot receiver object")
		}
		receivers.Put(participant, newReceiver)
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
