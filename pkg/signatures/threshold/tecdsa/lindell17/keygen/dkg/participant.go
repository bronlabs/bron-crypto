package dkg

import (
	"io"
	"math/big"

	"github.com/copperexchange/knox-primitives/pkg/commitments"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/paillier"
	"github.com/copperexchange/knox-primitives/pkg/proofs/paillier/lp"
	"github.com/copperexchange/knox-primitives/pkg/proofs/paillier/lpdl"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/merlin"
)

var _ lindell17.Participant = (*Participant)(nil)

type State struct {
	myXPrime          curves.Scalar
	myXDoublePrime    curves.Scalar
	myBigQPrime       curves.Point
	myBigQDoublePrime curves.Point
	myBigQWitness     commitments.Witness
	myPaillierPk      *paillier.PublicKey
	myPaillierSk      *paillier.SecretKey
	myRPrime          *big.Int
	myRDoublePrime    *big.Int

	theirBigQCommitment          map[integration.IdentityKey]commitments.Commitment
	theirBigQPrime               map[integration.IdentityKey]curves.Point
	theirBigQDoublePrime         map[integration.IdentityKey]curves.Point
	theirPaillierPublicKeys      map[integration.IdentityKey]*paillier.PublicKey
	theirPaillierEncryptedShares map[integration.IdentityKey]paillier.CipherText

	lpProvers                map[integration.IdentityKey]*lp.Prover
	lpVerifiers              map[integration.IdentityKey]*lp.Verifier
	lpdlPrimeProvers         map[integration.IdentityKey]*lpdl.Prover
	lpdlPrimeVerifiers       map[integration.IdentityKey]*lpdl.Verifier
	lpdlDoublePrimeProvers   map[integration.IdentityKey]*lpdl.Prover
	lpdlDoublePrimeVerifiers map[integration.IdentityKey]*lpdl.Verifier
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
	transcript        transcripts.Transcript
	prng              io.Reader

	round int
	state *State
}

const (
	transcriptAppLabel       = "COPPER_KNOX_LINDELL17_DKG"
	transcriptSessionIdLabel = "Lindell2017 DKG Session"
)

func (p *Participant) GetIdentityKey() integration.IdentityKey {
	return p.myIdentityKey
}

func (p *Participant) GetShamirId() int {
	return p.myShamirId
}

func (p *Participant) GetCohortConfig() *integration.CohortConfig {
	return p.cohortConfig
}

func NewBackupParticipant(myIdentityKey integration.IdentityKey, mySigningKeyShare *threshold.SigningKeyShare, publicKeyShares *threshold.PublicKeyShares, cohortConfig *integration.CohortConfig, prng io.Reader, sessionId []byte, transcript transcripts.Transcript) (participant *Participant, err error) {
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
	if transcript == nil {
		transcript = merlin.NewTranscript(transcriptAppLabel)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sessionId)

	_, idKeyToShamirId, myShamirId := integration.DeriveSharingIds(myIdentityKey, cohortConfig.Participants)

	return &Participant{
		myIdentityKey:     myIdentityKey,
		myShamirId:        myShamirId,
		mySigningKeyShare: mySigningKeyShare,
		publicKeyShares:   publicKeyShares,
		cohortConfig:      cohortConfig,
		idKeyToShamirId:   idKeyToShamirId,
		sessionId:         sessionId,
		transcript:        transcript,
		prng:              prng,
		round:             1,
		state:             &State{},
	}, nil
}
