package noninteractive_signing

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/sample"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/mult"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
	"gonum.org/v1/gonum/stat/combin"
)

const transcriptLabel = "COPPER_KRYPTON_TECDSA_DKLS24-"

var _ dkls24.Participant = (*PregenParticipant)(nil)

type PregenParticipant struct {
	prng io.Reader

	MyAuthKey   integration.AuthKey
	MySharingId int
	Shard       *dkls24.Shard

	UniqueSessionId     []byte
	CohortConfig        *integration.CohortConfig
	SessionParticipants map[CombiGroupHash]*hashset.HashSet[integration.IdentityKey]
	sessionSharingIds   map[CombiGroupHash][]int

	transcript             transcripts.Transcript
	subprotocols           map[CombiGroupHash]*SubProtocols
	state                  map[CombiGroupHash]*state
	tau                    int
	combinations           [][]int
	round                  int
	SharingIdToIdentityKey map[int]integration.IdentityKey
	IdentityKeyToSharingId map[types.IdentityHash]int

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
	phi_i                              []curves.Scalar
	sk_i                               []curves.Scalar
	r_i                                []curves.Scalar
	R_i                                []curves.Point
	cU_i                               []map[types.IdentityHash]curves.Scalar
	cV_i                               []map[types.IdentityHash]curves.Scalar
	pk_i                               []curves.Point
	Chi_i                              []map[types.IdentityHash]curves.Scalar
	witnessesOfCommitmentToInstanceKey []map[types.IdentityHash]commitments.Witness
	receivedCommitmentsToInstanceKey   []map[types.IdentityHash]commitments.Commitment
	receivedR_i                        []map[types.IdentityHash]curves.Point

	_ types.Incomparable
}

func (ic *PregenParticipant) GetAuthKey() integration.AuthKey {
	return ic.MyAuthKey
}

func (ic *PregenParticipant) GetSharingId() int {
	return ic.MySharingId
}

func (ic *PregenParticipant) GetCohortConfig() *integration.CohortConfig {
	return ic.CohortConfig
}

func (ic *PregenParticipant) IsSignatureAggregator() bool {
	for _, signatureAggregator := range ic.CohortConfig.Protocol.SignatureAggregators.Iter() {
		if signatureAggregator.PublicKey().Equal(ic.MyAuthKey.PublicKey()) {
			return true
		}
	}
	return false
}

func contains(s []int, target int) bool {
	for _, v := range s {
		if v == target {
			return true
		}
	}
	return false
}

// NewPregenParticipant constructs the interactive DKLs24 PregenParticipant.
func NewPregenParticipant(uniqueSessionId []byte, authKey integration.AuthKey, shard *dkls24.Shard, cohortConfig *integration.CohortConfig, tprng io.Reader, seededPrng csprng.CSPRNG, tau int, transcript transcripts.Transcript) (*PregenParticipant, error) {
	if err := validateInput(uniqueSessionId, cohortConfig, tau, shard); err != nil {
		return nil, errs.WrapInvalidArgument(err, "could not validate input")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptLabel, nil)
	}
	transcript.AppendMessages("DKLs24 Interactive Signing", uniqueSessionId)
	idToKey, keyToId, mySharingId := integration.DeriveSharingIds(authKey, cohortConfig.Participants)
	combinations := combin.Combinations(cohortConfig.Participants.Len(), cohortConfig.Protocol.Threshold)
	// only take combinations that contains mySharingId
	for i := 0; i < len(combinations); i++ {
		if !contains(combinations[i], mySharingId) {
			combinations = append(combinations[:i], combinations[i+1:]...)
			i--
		}
	}
	if len(combinations) == 0 {
		return nil, errs.NewInvalidArgument("no combinations of threshold %d and %d participants", cohortConfig.Protocol.Threshold, cohortConfig.Participants.Len())
	}
	sessionSharingIds := make(map[CombiGroupHash][]int)
	for _, combination := range combinations {
		if len(combination) == 0 {
			return nil, errs.NewInvalidArgument("empty combination")
		}
		sessionSharingIds[NewCombiGroupHash(combination)] = combination
	}
	sessionParticipants := make(map[CombiGroupHash]*hashset.HashSet[integration.IdentityKey])
	for group, sharingIds := range sessionSharingIds {
		sessionParticipants[group] = hashset.NewHashSet[integration.IdentityKey]([]integration.IdentityKey{})
		for _, sharingId := range sharingIds {
			sessionParticipants[group].Add(idToKey[sharingId])
		}
	}

	subprotocols := make(map[CombiGroupHash]*SubProtocols)
	for _, combination := range combinations {
		group := NewCombiGroupHash(combination)
		// step 0.2
		zeroShareSamplingParty, err := sample.NewParticipant(cohortConfig.CipherSuite.Curve, uniqueSessionId, authKey, shard.PairwiseSeeds, sessionParticipants[group], seededPrng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct zero share sampling party")
		}
		// step 0.3
		multipliers := make(map[types.IdentityHash]*Multiplication)
		for _, participant := range sessionParticipants[group].Iter() {
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
			multipliers = make(map[types.IdentityHash]*Multiplication)
			multipliers[participant.Hash()] = &Multiplication{
				Alice: alice,
				Bob:   bob,
			}
		}
		subprotocols[group] = &SubProtocols{
			zeroShareSampling: zeroShareSamplingParty,
			multiplication:    multipliers,
		}
	}
	st := make(map[CombiGroupHash]*state)
	for _, combination := range combinations {
		group := NewCombiGroupHash(combination)
		st[group] = &state{}
		st[group].witnessesOfCommitmentToInstanceKey = make([]map[types.IdentityHash]commitments.Witness, tau)
		st[group].Chi_i = make([]map[types.IdentityHash]curves.Scalar, tau)
		st[group].cU_i = make([]map[types.IdentityHash]curves.Scalar, tau)
		st[group].cV_i = make([]map[types.IdentityHash]curves.Scalar, tau)
		st[group].receivedCommitmentsToInstanceKey = make([]map[types.IdentityHash]commitments.Commitment, tau)
		st[group].receivedR_i = make([]map[types.IdentityHash]curves.Point, tau)
	}

	cosigner := &PregenParticipant{
		MyAuthKey:              authKey,
		CohortConfig:           cohortConfig,
		Shard:                  shard,
		UniqueSessionId:        uniqueSessionId,
		SessionParticipants:    sessionParticipants,
		sessionSharingIds:      sessionSharingIds,
		prng:                   tprng,
		transcript:             transcript,
		subprotocols:           subprotocols,
		state:                  st,
		MySharingId:            mySharingId,
		round:                  1,
		combinations:           combinations,
		SharingIdToIdentityKey: idToKey,
		IdentityKeyToSharingId: keyToId,
		tau:                    tau,
	}

	return cosigner, nil
}

func validateInput(uniqueSessionId []byte, cohortConfig *integration.CohortConfig, tau int, shard *dkls24.Shard) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if cohortConfig.Protocol == nil {
		return errs.NewIsNil("cohort config protocol is nil")
	}
	if shard == nil {
		return errs.NewMissing("shard is nil")
	}
	if tau <= 0 {
		return errs.NewInvalidArgument("tau is non-positive")
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
