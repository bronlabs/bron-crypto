package interactiveSigning

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
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

const transcriptLabel = "COPPER_KRYPTON_TECDSA_DKLS24-"

var _ dkls24.Participant = (*Cosigner)(nil)

type Cosigner struct {
	prng io.Reader

	MyAuthKey  integration.AuthKey
	MyShamirId int
	Shard      *dkls24.Shard

	UniqueSessionId       []byte
	CohortConfig          *integration.CohortConfig
	ShamirIdToIdentityKey map[int]integration.IdentityKey
	IdentityKeyToShamirId map[types.IdentityHash]int
	SessionParticipants   *hashset.HashSet[integration.IdentityKey]
	sessionShamirIDs      []int

	transcript transcripts.Transcript
	state      *signing.SignerState
	round      int

	_ types.Incomparable
}

func (ic *Cosigner) GetShard() *dkls24.Shard {
	return ic.Shard
}

func (ic *Cosigner) GetIdentityHashToSharingId() map[types.IdentityHash]int {
	return ic.IdentityKeyToShamirId
}

func (ic *Cosigner) GetPrng() io.Reader {
	return ic.prng
}

func (ic *Cosigner) GetSessionId() []byte {
	return ic.UniqueSessionId
}

func (ic *Cosigner) GetAuthKey() integration.AuthKey {
	return ic.MyAuthKey
}

func (ic *Cosigner) GetSharingId() int {
	return ic.MyShamirId
}

func (ic *Cosigner) GetCohortConfig() *integration.CohortConfig {
	return ic.CohortConfig
}

func (ic *Cosigner) IsSignatureAggregator() bool {
	for _, signatureAggregator := range ic.CohortConfig.Protocol.SignatureAggregators.Iter() {
		if signatureAggregator.PublicKey().Equal(ic.MyAuthKey.PublicKey()) {
			return true
		}
	}
	return false
}

// NewCosigner constructs the interactive DKLs24 cosigner.
func NewCosigner(uniqueSessionId []byte, authKey integration.AuthKey, sessionParticipants *hashset.HashSet[integration.IdentityKey], shard *dkls24.Shard, cohortConfig *integration.CohortConfig, tprng io.Reader, seededPrng csprng.CSPRNG, transcript transcripts.Transcript) (*Cosigner, error) {
	if err := validateInput(uniqueSessionId, cohortConfig, shard, sessionParticipants); err != nil {
		return nil, errs.WrapInvalidArgument(err, "could not validate input")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptLabel, nil)
	}
	transcript.AppendMessages("DKLs24 Interactive Signing", uniqueSessionId)

	shamirIdToIdentityKey, identityKeyToShamirId, myShamirId := integration.DeriveSharingIds(authKey, cohortConfig.Participants)
	sessionShamirIDs := make([]int, sessionParticipants.Len())
	i := -1
	for _, sessionParticipant := range sessionParticipants.Iter() {
		i++
		sessionShamirIDs[i] = identityKeyToShamirId[sessionParticipant.Hash()]
	}

	// step 0.2
	zeroShareParticipant, err := hjky.NewParticipant(uniqueSessionId, authKey, cohortConfig.CipherSuite.Curve.ScalarField(), cohortConfig.Protocol.Threshold, sessionParticipants.List(), tprng, transcript.Clone())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct zero share sampling party")
	}

	// step 0.3
	multipliers := make(map[types.IdentityHash]*signing.Multiplication, sessionParticipants.Len())
	for _, participant := range sessionParticipants.Iter() {
		if participant.PublicKey().Equal(authKey.PublicKey()) {
			continue
		}
		alice, err := mult.NewAlice(cohortConfig.CipherSuite.Curve, shard.PairwiseBaseOTs[participant.Hash()].AsReceiver, uniqueSessionId, tprng, seededPrng, transcript.Clone())
		if err != nil {
			return nil, errs.WrapFailed(err, "alice construction for participant %x", participant.PublicKey().ToAffineCompressed())
		}
		bob, err := mult.NewBob(cohortConfig.CipherSuite.Curve, shard.PairwiseBaseOTs[participant.Hash()].AsSender, uniqueSessionId, tprng, seededPrng, transcript.Clone())
		if err != nil {
			return nil, errs.WrapFailed(err, "bob construction for participant %x", participant.PublicKey().ToAffineCompressed())
		}
		multipliers[participant.Hash()] = &signing.Multiplication{
			Alice: alice,
			Bob:   bob,
		}
	}

	cosigner := &Cosigner{
		MyAuthKey:           authKey,
		CohortConfig:        cohortConfig,
		Shard:               shard,
		UniqueSessionId:     uniqueSessionId,
		SessionParticipants: sessionParticipants,
		sessionShamirIDs:    sessionShamirIDs,
		prng:                tprng,
		transcript:          transcript,
		state: &signing.SignerState{
			//InstanceKeyWitness:             make(map[types.IdentityHash]commitments.Witness),
			//Chi_i:                          make(map[types.IdentityHash]curves.Scalar),
			//Cu_i:                           make(map[types.IdentityHash]curves.Scalar),
			//Cv_i:                           make(map[types.IdentityHash]curves.Scalar),
			//ReceivedInstanceKeyCommitments: make(map[types.IdentityHash]commitments.Commitment),
			//ReceivedBigR_i:                 make(map[types.IdentityHash]curves.Point),
			Protocols: &signing.SubProtocols{
				ZeroShareParticipant: zeroShareParticipant,
				Multiplication:       multipliers,
			},
		},
		ShamirIdToIdentityKey: shamirIdToIdentityKey,
		IdentityKeyToShamirId: identityKeyToShamirId,
		MyShamirId:            myShamirId,
		round:                 1,
	}

	return cosigner, nil
}

func validateInput(uniqueSessionId []byte, cohortConfig *integration.CohortConfig, shard *dkls24.Shard, sessionParticipants *hashset.HashSet[integration.IdentityKey]) error {
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

	if sessionParticipants == nil {
		return errs.NewIsNil("invalid number of session participants")
	}
	if sessionParticipants.Len() != cohortConfig.Protocol.Threshold {
		return errs.NewInvalidLength("invalid number of session participants")
	}
	for _, sessionParticipant := range sessionParticipants.Iter() {
		if !cohortConfig.IsInCohort(sessionParticipant) {
			return errs.NewInvalidIdentifier("invalid session participant")
		}
	}
	if len(uniqueSessionId) == 0 {
		return errs.NewInvalidLength("invalid session id: %s", uniqueSessionId)
	}
	return nil
}
