package dkg

import (
	"github.com/copperexchange/knox-primitives/pkg/commitments"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/paillier"
	"github.com/copperexchange/knox-primitives/pkg/proofs/paillier/lp"
	"github.com/copperexchange/knox-primitives/pkg/proofs/paillier/lpdl"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/lindell17"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
	"github.com/cronokirby/saferith"
	"io"
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
	myRPrime          *saferith.Nat
	myRDoublePrime    *saferith.Nat

	theirBigQCommitment          map[helper_types.IdentityHash]commitments.Commitment
	theirBigQPrime               map[helper_types.IdentityHash]curves.Point
	theirBigQDoublePrime         map[helper_types.IdentityHash]curves.Point
	theirPaillierPublicKeys      map[helper_types.IdentityHash]*paillier.PublicKey
	theirPaillierEncryptedShares map[helper_types.IdentityHash]paillier.CipherText

	lpProvers                map[helper_types.IdentityHash]*lp.Prover
	lpVerifiers              map[helper_types.IdentityHash]*lp.Verifier
	lpdlPrimeProvers         map[helper_types.IdentityHash]*lpdl.Prover
	lpdlPrimeVerifiers       map[helper_types.IdentityHash]*lpdl.Verifier
	lpdlDoublePrimeProvers   map[helper_types.IdentityHash]*lpdl.Prover
	lpdlDoublePrimeVerifiers map[helper_types.IdentityHash]*lpdl.Verifier

	_ helper_types.Incomparable
}

type Participant struct {
	lindell17.Participant
	myIdentityKey     integration.IdentityKey
	mySharingId       int
	mySigningKeyShare *threshold.SigningKeyShare
	publicKeyShares   *threshold.PublicKeyShares
	cohortConfig      *integration.CohortConfig
	idKeyToSharingId  map[helper_types.IdentityHash]int
	sessionId         []byte
	transcript        transcripts.Transcript
	prng              io.Reader

	round int
	state *State

	_ helper_types.Incomparable
}

const (
	transcriptAppLabel       = "COPPER_KNOX_LINDELL17_DKG"
	transcriptSessionIdLabel = "Lindell2017 DKG Session"
)

func (p *Participant) GetIdentityKey() integration.IdentityKey {
	return p.myIdentityKey
}

func (p *Participant) GetSharingId() int {
	return p.mySharingId
}

func (p *Participant) GetCohortConfig() *integration.CohortConfig {
	return p.cohortConfig
}

func NewBackupParticipant(myIdentityKey integration.IdentityKey, mySigningKeyShare *threshold.SigningKeyShare, publicKeyShares *threshold.PublicKeyShares, cohortConfig *integration.CohortConfig, prng io.Reader, sessionId []byte, transcript transcripts.Transcript) (participant *Participant, err error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "cohort config is invalid")
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
		transcript = hagrid.NewTranscript(transcriptAppLabel)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sessionId)

	_, idKeyToSharingId, mySharingId := integration.DeriveSharingIds(myIdentityKey, cohortConfig.Participants)

	return &Participant{
		myIdentityKey:     myIdentityKey,
		mySharingId:       mySharingId,
		mySigningKeyShare: mySigningKeyShare,
		publicKeyShares:   publicKeyShares,
		cohortConfig:      cohortConfig,
		idKeyToSharingId:  idKeyToSharingId,
		sessionId:         sessionId,
		transcript:        transcript,
		prng:              prng,
		round:             1,
		state:             &State{},
	}, nil
}
