package dkg

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/commitments"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/paillier"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17"
	dlog "github.com/copperexchange/crypto-primitives-go/pkg/zkp/schnorr"
	"github.com/gtank/merlin"
	"io"
	"math/big"
)

var _ lindell17.Participant = (*Participant)(nil)

type ParticipantState struct {
	myXPrime         curves.Scalar
	myXBis           curves.Scalar
	myBigQPrimeProof *dlog.Proof
	myBigQBisProof   *dlog.Proof
	myBigQWitness    commitments.Witness
	myPaillierPk     *paillier.PublicKey
	myPaillierSk     *paillier.SecretKey
	myRPrime         *big.Int
	myRBis           *big.Int

	theirBigQCommitment map[integration.IdentityKey]commitments.Commitment
	theirBigQPrime      map[integration.IdentityKey]curves.Point
	theirBigQBis        map[integration.IdentityKey]curves.Point
}

type Participant struct {
	lindell17.Participant
	myIdentityKey     integration.IdentityKey
	myShamirId        int
	mySigningKeyShare *threshold.SigningKeyShare
	publicKeyShares   *threshold.PublicKeyShares
	cohortConfig      *integration.CohortConfig
	idKeyToShamirId   map[integration.IdentityKey]int
	sessionId         []byte
	prng              io.Reader

	round int
	state *ParticipantState
}

func (participant *Participant) GetIdentityKey() integration.IdentityKey {
	return participant.myIdentityKey
}

func (participant *Participant) GetShamirId() int {
	return participant.myShamirId
}

func (participant *Participant) GetCohortConfig() *integration.CohortConfig {
	return participant.cohortConfig
}

func NewBackupParticipant(myIdentityKey integration.IdentityKey, mySigningKeyShare *threshold.SigningKeyShare, publicKeyShares *threshold.PublicKeyShares, cohortConfig *integration.CohortConfig, prng io.Reader, sessionId []byte, transcript *merlin.Transcript) (participant *Participant, err error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if cohortConfig.PreSignatureComposer != nil {
		return nil, errs.NewVerificationFailed("can't set presignature composer if cosigner is interactive")
	}
	if err := mySigningKeyShare.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "could not validate signing key share")
	}
	if myIdentityKey == nil {
		return nil, errs.NewIsNil("my identity key is nil")
	}
	if sessionId == nil || len(sessionId) == 0 {
		return nil, errs.NewInvalidArgument("invalid session id: %s", sessionId)
	}
	//if transcript == nil {
	//	transcript = merlin.NewTranscript(transcriptLabel)
	//}
	//transcript.AppendMessage([]byte(transcriptSessionIdLabel), sessionId)

	_, idKeyToShamirId, myShamirId := integration.DeriveSharingIds(myIdentityKey, cohortConfig.Participants)

	return &Participant{
		myIdentityKey:     myIdentityKey,
		myShamirId:        myShamirId,
		mySigningKeyShare: mySigningKeyShare,
		publicKeyShares:   publicKeyShares,
		cohortConfig:      cohortConfig,
		idKeyToShamirId:   idKeyToShamirId,
		sessionId:         sessionId,
		prng:              prng,
		round:             1,
		state:             &ParticipantState{},
	}, nil
}
