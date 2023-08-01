package interactive

import (
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/commitments"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17"
	"github.com/copperexchange/crypto-primitives-go/pkg/transcript"
	"github.com/copperexchange/crypto-primitives-go/pkg/transcript/merlin"
	"github.com/copperexchange/crypto-primitives-go/pkg/zkp/schnorr"
)

const (
	transcriptLabel          = "COPPER_KNOX_LINDELL2017_INTERACTIVE_SIGN"
	transcriptSessionIdLabel = "COPPER_KNOX_LINDELL2017_INTERACTIVE_SIGN_SESSION_ID"
)

var _ lindell17.Participant = (*PrimaryCosigner)(nil)
var _ lindell17.Participant = (*SecondaryCosigner)(nil)

type Cosigner struct {
	lindell17.Participant

	prng          io.Reader
	cohortConfig  *integration.CohortConfig
	sessionId     []byte
	transcript    transcript.Transcript
	myIdentityKey integration.IdentityKey
	myShamirId    int
	myShard       *lindell17.Shard
	round         int
}

type PrimaryCosignerState struct {
	k1             curves.Scalar
	k1Proof        *schnorr.Proof
	k1ProofWitness []byte
	bigR           curves.Point
	r              curves.Scalar
	k1PublicKey    curves.Point
	k2PublicKey    curves.Point
}

type PrimaryCosigner struct {
	Cosigner

	secondaryIdentityKey integration.IdentityKey
	secondaryShamirId    int
	state                *PrimaryCosignerState
}

type SecondaryCosignerState struct {
	k1ProofCommitment commitments.Commitment
	k2                curves.Scalar
	r                 curves.Scalar
	k1PublicKey       curves.Point
	k2PublicKey       curves.Point
}

type SecondaryCosigner struct {
	Cosigner

	primaryIdentityKey integration.IdentityKey
	primaryShamirId    int
	state              *SecondaryCosignerState
}

func (cosigner *Cosigner) GetIdentityKey() integration.IdentityKey {
	return cosigner.myIdentityKey
}

func (cosigner *Cosigner) GetShamirId() int {
	return cosigner.myShamirId
}

func (cosigner *Cosigner) GetCohortConfig() *integration.CohortConfig {
	return cosigner.cohortConfig
}

func (cosigner *Cosigner) IsSignatureAggregator() bool {
	for _, signatureAggregator := range cosigner.cohortConfig.SignatureAggregators {
		if signatureAggregator.PublicKey().Equal(cosigner.myIdentityKey.PublicKey()) {
			return true
		}
	}
	return false
}

func NewPrimaryCosigner(myIdentityKey integration.IdentityKey, secondaryIdentityKey integration.IdentityKey, myShard *lindell17.Shard, cohortConfig *integration.CohortConfig, sessionId []byte, transcript transcript.Transcript, prng io.Reader) (primaryCosigner *PrimaryCosigner, err error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if cohortConfig.PreSignatureComposer != nil {
		return nil, errs.NewVerificationFailed("can't set presignature composer if cosigner is interactive")
	}
	if err := myShard.SigningKeyShare.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "could not validate signing key share")
	}
	if myIdentityKey == nil {
		return nil, errs.NewIsNil("my identity key is nil")
	}
	if secondaryIdentityKey == nil {
		return nil, errs.NewIsNil("primary identity key is nil")
	}
	if sessionId == nil || len(sessionId) == 0 {
		return nil, errs.NewInvalidArgument("invalid session id: %s", sessionId)
	}
	if transcript == nil {
		transcript = merlin.NewTranscript(transcriptLabel)
	}
	transcript.AppendMessage([]byte(transcriptSessionIdLabel), sessionId)

	_, identityKeyToShamirId, myShamirId := integration.DeriveSharingIds(myIdentityKey, cohortConfig.Participants)
	primaryCosigner = &PrimaryCosigner{
		Cosigner: Cosigner{
			myIdentityKey: myIdentityKey,
			myShamirId:    myShamirId,
			myShard:       myShard,
			cohortConfig:  cohortConfig,
			sessionId:     sessionId,
			transcript:    transcript,
			prng:          prng,
			round:         1,
		},
		secondaryIdentityKey: secondaryIdentityKey,
		secondaryShamirId:    identityKeyToShamirId[secondaryIdentityKey],
		state:                &PrimaryCosignerState{},
	}
	if !primaryCosigner.IsSignatureAggregator() {
		return nil, errs.NewFailed("interactive primary cosigner must be signature aggregator")
	}

	return primaryCosigner, nil
}

func NewSecondaryCosigner(myIdentityKey integration.IdentityKey, primaryIdentityKey integration.IdentityKey, myShard *lindell17.Shard, cohortConfig *integration.CohortConfig, sessionId []byte, transcript transcript.Transcript, prng io.Reader) (secondaryCosigner *SecondaryCosigner, err error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if cohortConfig.PreSignatureComposer != nil {
		return nil, errs.NewVerificationFailed("can't set presignature composer if cosigner is interactive")
	}
	if err := myShard.SigningKeyShare.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "could not validate signing key share")
	}
	if myIdentityKey == nil {
		return nil, errs.NewIsNil("my identity key is nil")
	}
	if primaryIdentityKey == nil {
		return nil, errs.NewIsNil("primary identity key is nil")
	}
	if sessionId == nil || len(sessionId) == 0 {
		return nil, errs.NewInvalidArgument("invalid session id: %s", sessionId)
	}
	if transcript == nil {
		transcript = merlin.NewTranscript(transcriptLabel)
	}
	transcript.AppendMessage([]byte(transcriptSessionIdLabel), sessionId)

	_, keyToId, myShamirId := integration.DeriveSharingIds(myIdentityKey, cohortConfig.Participants)
	return &SecondaryCosigner{
		Cosigner: Cosigner{
			myIdentityKey: myIdentityKey,
			myShamirId:    myShamirId,
			myShard:       myShard,
			cohortConfig:  cohortConfig,
			sessionId:     sessionId,
			transcript:    transcript,
			prng:          prng,
			round:         1,
		},
		primaryIdentityKey: primaryIdentityKey,
		primaryShamirId:    keyToId[primaryIdentityKey],
		state:              &SecondaryCosignerState{},
	}, nil
}
