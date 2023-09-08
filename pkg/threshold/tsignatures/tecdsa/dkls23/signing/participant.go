package signing

import (
	"io"

	"github.com/copperexchange/krypton/pkg/base/curves"
	"github.com/copperexchange/krypton/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton/pkg/base/errs"
	"github.com/copperexchange/krypton/pkg/base/types"
	"github.com/copperexchange/krypton/pkg/base/types/integration"
	"github.com/copperexchange/krypton/pkg/commitments"
	"github.com/copperexchange/krypton/pkg/csprng"
	"github.com/copperexchange/krypton/pkg/threshold/sharing/zero/przs/sample"
	"github.com/copperexchange/krypton/pkg/threshold/tsignatures/tecdsa/dkls23"
	"github.com/copperexchange/krypton/pkg/threshold/tsignatures/tecdsa/dkls23/mult"
	"github.com/copperexchange/krypton/pkg/transcripts"
	"github.com/copperexchange/krypton/pkg/transcripts/hagrid"
)

const transcriptLabel = "COPPER_KRYPTON_TECDSA_DKLS23-"

var _ dkls23.Participant = (*Cosigner)(nil)

type Cosigner struct {
	prng io.Reader

	MyIdentityKey integration.IdentityKey
	MyShamirId    int
	Shard         *dkls23.Shard

	UniqueSessionId       []byte
	CohortConfig          *integration.CohortConfig
	ShamirIdToIdentityKey map[int]integration.IdentityKey
	IdentityKeyToShamirId map[types.IdentityHash]int
	SessionParticipants   *hashset.HashSet[integration.IdentityKey]
	sessionShamirIDs      []int

	transcript   transcripts.Transcript
	subprotocols *SubProtocols
	state        *state
	round        int

	_ types.Incomparable
}

type SubProtocols struct {
	// use to get the secret key msak (zeta_i)
	zeroShareSampling *sample.Participant
	// pairwise multiplication protocol ie. each party acts as alice and bob against every party
	multiplication map[types.IdentityHash]*Multiplication

	_ types.Incomparable
}

// Corresponding participant objects for pairwise multiplication subprotocols.
type Multiplication struct {
	Alice *mult.Alice
	Bob   *mult.Bob

	_ types.Incomparable
}

type state struct {
	phi_i                              curves.Scalar
	sk_i                               curves.Scalar
	r_i                                curves.Scalar
	R_i                                curves.Point
	cU_i                               map[types.IdentityHash]curves.Scalar
	cV_i                               map[types.IdentityHash]curves.Scalar
	pk_i                               curves.Point
	Chi_i                              map[types.IdentityHash]curves.Scalar
	witnessesOfCommitmentToInstanceKey map[types.IdentityHash]commitments.Witness
	receivedCommitmentsToInstanceKey   map[types.IdentityHash]commitments.Commitment
	receivedR_i                        map[types.IdentityHash]curves.Point

	_ types.Incomparable
}

func (ic *Cosigner) GetIdentityKey() integration.IdentityKey {
	return ic.MyIdentityKey
}

func (ic *Cosigner) GetSharingId() int {
	return ic.MyShamirId
}

func (ic *Cosigner) GetCohortConfig() *integration.CohortConfig {
	return ic.CohortConfig
}

func (ic *Cosigner) IsSignatureAggregator() bool {
	for _, signatureAggregator := range ic.CohortConfig.Protocol.SignatureAggregators.Iter() {
		if signatureAggregator.PublicKey().Equal(ic.MyIdentityKey.PublicKey()) {
			return true
		}
	}
	return false
}

// NewCosigner constructs the interactive DKLs23 cosigner.
func NewCosigner(uniqueSessionId []byte, identityKey integration.IdentityKey, sessionParticipants *hashset.HashSet[integration.IdentityKey], shard *dkls23.Shard, cohortConfig *integration.CohortConfig, tprng io.Reader, seededPrng csprng.CSPRNG, transcript transcripts.Transcript) (*Cosigner, error) {
	if err := validateInput(uniqueSessionId, cohortConfig, shard, sessionParticipants); err != nil {
		return nil, errs.WrapInvalidArgument(err, "could not validate input")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptLabel, nil)
	}
	transcript.AppendMessages("DKLs23 Interactive Signing", uniqueSessionId)

	shamirIdToIdentityKey, identityKeyToShamirId, myShamirId := integration.DeriveSharingIds(identityKey, cohortConfig.Participants)
	sessionShamirIDs := make([]int, sessionParticipants.Len())
	i := -1
	for _, sessionParticipant := range sessionParticipants.Iter() {
		i++
		sessionShamirIDs[i] = identityKeyToShamirId[sessionParticipant.Hash()]
	}

	// step 0.2
	zeroShareSamplingParty, err := sample.NewParticipant(cohortConfig, uniqueSessionId, identityKey, shard.PairwiseSeeds, sessionParticipants, seededPrng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct zero share sampling party")
	}
	// step 0.3
	multipliers := make(map[types.IdentityHash]*Multiplication, sessionParticipants.Len())
	for _, participant := range sessionParticipants.Iter() {
		if participant.PublicKey().Equal(identityKey.PublicKey()) {
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
		multipliers[participant.Hash()] = &Multiplication{
			Alice: alice,
			Bob:   bob,
		}
	}

	cosigner := &Cosigner{
		MyIdentityKey:       identityKey,
		CohortConfig:        cohortConfig,
		Shard:               shard,
		SessionParticipants: sessionParticipants,
		sessionShamirIDs:    sessionShamirIDs,
		prng:                tprng,
		transcript:          transcript,
		subprotocols: &SubProtocols{
			zeroShareSampling: zeroShareSamplingParty,
			multiplication:    multipliers,
		},
		state: &state{
			witnessesOfCommitmentToInstanceKey: map[types.IdentityHash]commitments.Witness{},
			Chi_i:                              map[types.IdentityHash]curves.Scalar{},
			cU_i:                               map[types.IdentityHash]curves.Scalar{},
			cV_i:                               map[types.IdentityHash]curves.Scalar{},
			receivedCommitmentsToInstanceKey:   map[types.IdentityHash]commitments.Commitment{},
			receivedR_i:                        map[types.IdentityHash]curves.Point{},
		},
		ShamirIdToIdentityKey: shamirIdToIdentityKey,
		IdentityKeyToShamirId: identityKeyToShamirId,
		MyShamirId:            myShamirId,
		round:                 1,
	}

	return cosigner, nil
}

func validateInput(uniqueSessionId []byte, cohortConfig *integration.CohortConfig, shard *dkls23.Shard, sessionParticipants *hashset.HashSet[integration.IdentityKey]) error {
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
