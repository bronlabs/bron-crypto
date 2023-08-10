package interactive

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/commitments"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashmap"
	"github.com/copperexchange/knox-primitives/pkg/sharing/zero/sample"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23/mult"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/merlin"
)

const transcriptLabel = "COPPER_KNOX_TECDSA_DKLS23-"

var _ dkls23.Participant = (*Cosigner)(nil)

type Cosigner struct {
	prng io.Reader

	MyIdentityKey integration.IdentityKey
	MySharing     int
	Shard         *dkls23.Shard

	UniqueSessionId        []byte
	CohortConfig           *integration.CohortConfig
	SharingToIdentityKey   map[int]integration.IdentityKey
	IdentityKeyToSharingId *hashmap.HashMap[integration.IdentityKey, int]
	SessionParticipants    []integration.IdentityKey
	sessionShamirIDs       []int

	transcript   transcripts.Transcript
	subprotocols *SubProtocols
	state        *state
	round        int
}

type SubProtocols struct {
	// use to get the secret key msak (zeta_i)
	zeroShareSampling *sample.Participant
	// pairwise multiplication protocol ie. each party acts as alice and bob against every party
	multiplication map[integration.IdentityKey]*Multiplication
}

// Corresponding participant objects for pairwise multiplication subprotocols.
type Multiplication struct {
	Alice *mult.Alice
	Bob   *mult.Bob
}

type state struct {
	phi_i                              curves.Scalar
	sk_i                               curves.Scalar
	r_i                                curves.Scalar
	R_i                                curves.Point
	cU_i                               map[integration.IdentityKey]curves.Scalar
	cV_i                               map[integration.IdentityKey]curves.Scalar
	pk_i                               curves.Point
	Chi_i                              map[integration.IdentityKey]curves.Scalar
	witnessesOfCommitmentToInstanceKey map[integration.IdentityKey]commitments.Witness
	receivedCommitmentsToInstanceKey   map[integration.IdentityKey]commitments.Commitment
	receivedR_i                        map[integration.IdentityKey]curves.Point
}

func (ic *Cosigner) GetIdentityKey() integration.IdentityKey {
	return ic.MyIdentityKey
}

func (ic *Cosigner) GetSharingId() int {
	return ic.MySharing
}

func (ic *Cosigner) GetCohortConfig() *integration.CohortConfig {
	return ic.CohortConfig
}

func (ic *Cosigner) IsSignatureAggregator() bool {
	for _, signatureAggregator := range ic.CohortConfig.SignatureAggregators {
		if signatureAggregator.PublicKey().Equal(ic.MyIdentityKey.PublicKey()) {
			return true
		}
	}
	return false
}

// NewCosigner constructs the interactive DKLs23 cosigner.
func NewCosigner(uniqueSessionId []byte, identityKey integration.IdentityKey, sessionParticipants []integration.IdentityKey, shard *dkls23.Shard, cohortConfig *integration.CohortConfig, prng io.Reader, transcript transcripts.Transcript) (*Cosigner, error) {
	if err := validateInput(uniqueSessionId, cohortConfig, shard, sessionParticipants); err != nil {
		return nil, errs.WrapInvalidArgument(err, "could not validate input")
	}
	if transcript == nil {
		transcript = merlin.NewTranscript(transcriptLabel)
	}
	transcript.AppendMessages("DKLs23 Interactive Signing", uniqueSessionId)
	tprng, err := transcript.NewReader("witness", shard.SigningKeyShare.Share.Bytes(), prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct transcript-based prng")
	}

	shamirIdToIdentityKey, identityKeyToSharing, mySharing := integration.DeriveSharingIds(identityKey, cohortConfig.Participants)
	sessionShamirIDs := make([]int, len(sessionParticipants))
	var exists bool
	for i := 0; i < len(sessionParticipants); i++ {
		sessionShamirIDs[i], exists = identityKeyToSharing.Get(sessionParticipants[i])
		if !exists {
			return nil, errs.NewFailed("identity key %x not found in identityKeyToSharing", sessionParticipants[i].PublicKey().ToAffineCompressed())
		}
	}

	// step 0.2
	zeroShareSamplingParty, err := sample.NewParticipant(cohortConfig.CipherSuite.Curve, uniqueSessionId, identityKey, shard.PairwiseSeeds, sessionParticipants)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct zero share sampling party")
	}
	// step 0.3
	multipliers := make(map[integration.IdentityKey]*Multiplication, len(sessionParticipants))
	for _, participant := range sessionParticipants {
		if participant.PublicKey().Equal(identityKey.PublicKey()) {
			continue
		}
		pairwiseBaseOT, exists := shard.PairwiseBaseOTs.Get(participant)
		if !exists {
			return nil, errs.NewFailed("pairwise base OT not found for participant %x", participant.PublicKey().ToAffineCompressed())
		}
		alice, err := mult.NewAlice(cohortConfig.CipherSuite.Curve, pairwiseBaseOT.AsReceiver, uniqueSessionId, prng, transcript.Clone())
		if err != nil {
			return nil, errs.WrapFailed(err, "alice construction for participant %x", participant.PublicKey().ToAffineCompressed())
		}
		bob, err := mult.NewBob(cohortConfig.CipherSuite.Curve, pairwiseBaseOT.AsSender, uniqueSessionId, prng, transcript.Clone())
		if err != nil {
			return nil, errs.WrapFailed(err, "bob construction for participant %x", participant.PublicKey().ToAffineCompressed())
		}
		multipliers[participant] = &Multiplication{
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
			witnessesOfCommitmentToInstanceKey: map[integration.IdentityKey]commitments.Witness{},
			Chi_i:                              map[integration.IdentityKey]curves.Scalar{},
			cU_i:                               map[integration.IdentityKey]curves.Scalar{},
			cV_i:                               map[integration.IdentityKey]curves.Scalar{},
			receivedCommitmentsToInstanceKey:   map[integration.IdentityKey]commitments.Commitment{},
			receivedR_i:                        map[integration.IdentityKey]curves.Point{},
		},
		SharingToIdentityKey:   shamirIdToIdentityKey,
		IdentityKeyToSharingId: identityKeyToSharing,
		MySharing:              mySharing,
		round:                  1,
	}

	return cosigner, nil
}

func validateInput(uniqueSessionId []byte, cohortConfig *integration.CohortConfig, shard *dkls23.Shard, sessionParticipants []integration.IdentityKey) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if cohortConfig.PreSignatureComposer != nil {
		return errs.NewVerificationFailed("can't set presignature composer if cosigner is interactive")
	}
	if shard == nil {
		return errs.NewMissing("shard is nil")
	}
	// TODO: implement full validation with base ots and seeds etc
	if err := shard.SigningKeyShare.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "could not validate signing key share")
	}

	if sessionParticipants == nil {
		return errs.NewIsNil("invalid number of session participants")
	}
	if len(sessionParticipants) != cohortConfig.Threshold {
		return errs.NewInvalidLength("invalid number of session participants")
	}
	for _, sessionParticipant := range sessionParticipants {
		if !cohortConfig.IsInCohort(sessionParticipant) {
			return errs.NewInvalidIdentifier("invalid session participant")
		}
	}
	if len(uniqueSessionId) == 0 {
		return errs.NewInvalidLength("invalid session id: %s", uniqueSessionId)
	}
	return nil
}
