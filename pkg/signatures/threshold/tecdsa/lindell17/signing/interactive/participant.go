package interactive

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/commitments"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/merlin"
)

const (
	transcriptLabel          = "COPPER_KNOX_LINDELL2017_INTERACTIVE_SIGN"
	transcriptSessionIdLabel = "COPPER_KNOX_LINDELL2017_INTERACTIVE_SIGN_SESSION_ID"
)

var (
	_ lindell17.Participant = (*PrimaryCosigner)(nil)
	_ lindell17.Participant = (*SecondaryCosigner)(nil)
)

type Cosigner struct {
	lindell17.Participant

	prng io.Reader
	// My Cohort config
	cohortConfig  *integration.CohortConfig
	sessionId     []byte
	transcript    transcripts.Transcript
	myIdentityKey integration.IdentityKey
	mySharingId   int
	myShard       *lindell17.Shard
	round         int
}

type PrimaryCosignerState struct {
	k1           curves.Scalar
	bigR1Witness []byte
	bigR         curves.Point
	r            curves.Scalar
	bigR1        curves.Point
}

type PrimaryCosigner struct {
	Cosigner

	secondaryIdentityKey integration.IdentityKey
	secondarySharing     int
	state                *PrimaryCosignerState
}

type SecondaryCosignerState struct {
	bigR1Commitment commitments.Commitment
	k2              curves.Scalar
	bigR2           curves.Point
}

type SecondaryCosigner struct {
	Cosigner

	primaryIdentityKey integration.IdentityKey
	primarySharingId   int
	state              *SecondaryCosignerState
}

func (cosigner *Cosigner) GetIdentityKey() integration.IdentityKey {
	return cosigner.myIdentityKey
}

func (cosigner *Cosigner) GetSharingId() int {
	return cosigner.mySharingId
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

func NewPrimaryCosigner(myIdentityKey, secondaryIdentityKey integration.IdentityKey, myShard *lindell17.Shard, cohortConfig *integration.CohortConfig, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (primaryCosigner *PrimaryCosigner, err error) {
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
	if len(sessionId) == 0 {
		return nil, errs.NewInvalidArgument("invalid session id: %s", sessionId)
	}
	if transcript == nil {
		transcript = merlin.NewTranscript(transcriptLabel)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sessionId)

	_, identityKeyToSharing, mySharing := integration.DeriveSharingIds(myIdentityKey, cohortConfig.Participants)
	sharingId, exists := identityKeyToSharing.Get(secondaryIdentityKey)
	if !exists {
		return nil, errs.NewVerificationFailed("secondary identity key is not part of cohort")
	}
	primaryCosigner = &PrimaryCosigner{
		Cosigner: Cosigner{
			myIdentityKey: myIdentityKey,
			mySharingId:   mySharing,
			myShard:       myShard,
			cohortConfig:  cohortConfig,
			sessionId:     sessionId,
			transcript:    transcript,
			prng:          prng,
			round:         1,
		},
		secondaryIdentityKey: secondaryIdentityKey,
		secondarySharing:     sharingId,
		state:                &PrimaryCosignerState{},
	}
	if !primaryCosigner.IsSignatureAggregator() {
		return nil, errs.NewFailed("interactive primary cosigner must be signature aggregator")
	}

	return primaryCosigner, nil
}

func NewSecondaryCosigner(myIdentityKey, primaryIdentityKey integration.IdentityKey, myShard *lindell17.Shard, cohortConfig *integration.CohortConfig, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (secondaryCosigner *SecondaryCosigner, err error) {
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
	if len(sessionId) == 0 {
		return nil, errs.NewInvalidArgument("invalid session id: %s", sessionId)
	}
	if transcript == nil {
		transcript = merlin.NewTranscript(transcriptLabel)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sessionId)

	_, keyToId, mySharing := integration.DeriveSharingIds(myIdentityKey, cohortConfig.Participants)
	id, exists := keyToId.Get(primaryIdentityKey)
	if !exists {
		return nil, errs.NewVerificationFailed("primary identity key is not part of cohort")
	}
	return &SecondaryCosigner{
		Cosigner: Cosigner{
			myIdentityKey: myIdentityKey,
			mySharingId:   mySharing,
			myShard:       myShard,
			cohortConfig:  cohortConfig,
			sessionId:     sessionId,
			transcript:    transcript,
			prng:          prng,
			round:         1,
		},
		primaryIdentityKey: primaryIdentityKey,
		primarySharingId:   id,
		state:              &SecondaryCosignerState{},
	}, nil
}
