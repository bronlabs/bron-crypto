package noninteractiveSigning

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/hjky"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/mult"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/signing"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const transcriptLabel = "COPPER_KRYPTON_PREGEN_DKLS24-"

var _ signing.Participant = (*PreGenParticipant)(nil)

type PreGenParticipant struct {
	prng io.Reader

	Tau        int
	MyAuthKey  integration.AuthKey
	MyShamirId int
	Shard      *dkls24.Shard

	UniqueSessionId       []byte
	CohortConfig          *integration.CohortConfig
	ShamirIdToIdentityKey map[int]integration.IdentityKey
	IdentityKeyToShamirId map[types.IdentityHash]int

	transcript transcripts.Transcript
	state      []*signing.SignerState
	round      int

	_ types.Incomparable
}

func (p *PreGenParticipant) GetShard() *dkls24.Shard {
	return p.Shard
}

func (p *PreGenParticipant) GetIdentityHashToSharingId() map[types.IdentityHash]int {
	return p.IdentityKeyToShamirId
}

func (p *PreGenParticipant) GetPrng() io.Reader {
	return p.prng
}

func (p *PreGenParticipant) GetSessionId() []byte {
	return p.UniqueSessionId
}

func (p *PreGenParticipant) GetAuthKey() integration.AuthKey {
	return p.MyAuthKey
}

func (p *PreGenParticipant) GetSharingId() int {
	return p.MyShamirId
}

func (p *PreGenParticipant) GetCohortConfig() *integration.CohortConfig {
	return p.CohortConfig
}

func (p *PreGenParticipant) IsSignatureAggregator() bool {
	for _, signatureAggregator := range p.CohortConfig.Protocol.SignatureAggregators.Iter() {
		if signatureAggregator.PublicKey().Equal(p.MyAuthKey.PublicKey()) {
			return true
		}
	}
	return false
}

func NewPreGenParticipant(tau int, myAuthKey integration.AuthKey, myShard *dkls24.Shard, uniqueSessionId []byte, cohortConfig *integration.CohortConfig, transcript transcripts.Transcript, prng io.Reader, seededPrng csprng.CSPRNG) (participant *PreGenParticipant, err error) {
	if err := validateInput(uniqueSessionId, cohortConfig, myShard); err != nil {
		return nil, errs.WrapInvalidArgument(err, "could not validate input")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptLabel, nil)
	}
	transcript.AppendMessages("DKLs24 Interactive Signing", uniqueSessionId)

	shamirIdToIdentityKey, identityKeyToShamirId, myShamirId := integration.DeriveSharingIds(myAuthKey, cohortConfig.Participants)

	state := make([]*signing.SignerState, tau)
	for t := 0; t < tau; t++ {
		// step 0.2
		zeroShareParticipant, err := hjky.NewParticipant(uniqueSessionId, myAuthKey, cohortConfig.CipherSuite.Curve.ScalarField(), cohortConfig.Protocol.Threshold, cohortConfig.Participants.List(), prng, transcript.Clone())
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct zero share sampling party")
		}
		// step 0.3
		multipliers := make(map[types.IdentityHash]*signing.Multiplication)
		for _, participant := range cohortConfig.Participants.Iter() {
			if participant.PublicKey().Equal(myAuthKey.PublicKey()) {
				continue
			}
			alice, err := mult.NewAlice(cohortConfig.CipherSuite.Curve, myShard.PairwiseBaseOTs[participant.Hash()].AsReceiver, uniqueSessionId, prng, seededPrng, transcript.Clone())
			if err != nil {
				return nil, errs.WrapFailed(err, "alice construction for participant %x", participant.PublicKey().ToAffineCompressed())
			}
			bob, err := mult.NewBob(cohortConfig.CipherSuite.Curve, myShard.PairwiseBaseOTs[participant.Hash()].AsSender, uniqueSessionId, prng, seededPrng, transcript.Clone())
			if err != nil {
				return nil, errs.WrapFailed(err, "bob construction for participant %x", participant.PublicKey().ToAffineCompressed())
			}
			multipliers[participant.Hash()] = &signing.Multiplication{
				Alice: alice,
				Bob:   bob,
			}
		}
		state[t] = &signing.SignerState{
			Protocols: &signing.SubProtocols{
				ZeroShareParticipant: zeroShareParticipant,
				Multiplication:       multipliers,
			},
		}
	}

	cosigner := &PreGenParticipant{
		Tau:                   tau,
		MyAuthKey:             myAuthKey,
		CohortConfig:          cohortConfig,
		Shard:                 myShard,
		UniqueSessionId:       uniqueSessionId,
		prng:                  prng,
		transcript:            transcript,
		state:                 state,
		ShamirIdToIdentityKey: shamirIdToIdentityKey,
		IdentityKeyToShamirId: identityKeyToShamirId,
		MyShamirId:            myShamirId,
		round:                 1,
	}

	return cosigner, nil
}

func validateInput(uniqueSessionId []byte, cohortConfig *integration.CohortConfig, shard *dkls24.Shard) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if cohortConfig.Protocol == nil {
		return errs.NewIsNil("cohort config protocol is nil")
	}
	if shard == nil {
		return errs.NewMissing("shard is nil")
	}
	// TODO: implement full validation with base ots and seeds etc
	if err := shard.Validate(cohortConfig); err != nil {
		return errs.WrapVerificationFailed(err, "could not validate shard")
	}

	if len(uniqueSessionId) == 0 {
		return errs.NewInvalidLength("invalid session id: %s", uniqueSessionId)
	}
	return nil
}
