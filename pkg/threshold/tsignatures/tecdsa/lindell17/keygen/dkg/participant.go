package dkg

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/lp"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/paillier/lpdl"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
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

	theirBigQCommitment          map[types.IdentityHash]commitments.Commitment
	theirBigQPrime               map[types.IdentityHash]curves.Point
	theirBigQDoublePrime         map[types.IdentityHash]curves.Point
	theirPaillierPublicKeys      map[types.IdentityHash]*paillier.PublicKey
	theirPaillierEncryptedShares map[types.IdentityHash]*paillier.CipherText

	lpProvers                map[types.IdentityHash]*lp.Prover
	lpVerifiers              map[types.IdentityHash]*lp.Verifier
	lpdlPrimeProvers         map[types.IdentityHash]*lpdl.Prover
	lpdlPrimeVerifiers       map[types.IdentityHash]*lpdl.Verifier
	lpdlDoublePrimeProvers   map[types.IdentityHash]*lpdl.Prover
	lpdlDoublePrimeVerifiers map[types.IdentityHash]*lpdl.Verifier

	_ types.Incomparable
}

type Participant struct {
	lindell17.Participant
	myAuthKey         integration.AuthKey
	mySharingId       int
	mySigningKeyShare *tsignatures.SigningKeyShare
	publicKeyShares   *tsignatures.PublicKeyShares
	cohortConfig      *integration.CohortConfig
	idKeyToSharingId  map[types.IdentityHash]int
	sessionId         []byte
	transcript        transcripts.Transcript
	prng              io.Reader

	round int
	state *State

	_ types.Incomparable
}

const (
	transcriptAppLabel       = "COPPER_KRYPTON_LINDELL17_DKG"
	transcriptSessionIdLabel = "Lindell2017 DKG Session"
)

func (p *Participant) GetAuthKey() integration.AuthKey {
	return p.myAuthKey
}

func (p *Participant) GetSharingId() int {
	return p.mySharingId
}

func (p *Participant) GetCohortConfig() *integration.CohortConfig {
	return p.cohortConfig
}

func NewBackupParticipant(myAuthKey integration.AuthKey, mySigningKeyShare *tsignatures.SigningKeyShare, publicKeyShares *tsignatures.PublicKeyShares, cohortConfig *integration.CohortConfig, prng io.Reader, sessionId []byte, transcript transcripts.Transcript) (participant *Participant, err error) {
	err = validateInputs(myAuthKey, mySigningKeyShare, publicKeyShares, cohortConfig, prng, sessionId)
	if err != nil {
		return nil, errs.WrapInvalidArgument(err, "invalid input arguments")
	}

	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptAppLabel, nil)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sessionId)

	_, idKeyToSharingId, mySharingId := integration.DeriveSharingIds(myAuthKey, cohortConfig.Participants)

	return &Participant{
		myAuthKey:         myAuthKey,
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

func validateInputs(myAuthKey integration.AuthKey, mySigningKeyShare *tsignatures.SigningKeyShare, publicKeyShares *tsignatures.PublicKeyShares, cohortConfig *integration.CohortConfig, prng io.Reader, sessionId []byte) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if cohortConfig.Protocol == nil {
		return errs.NewIsNil("cohort config protocol is nil")
	}
	if err := mySigningKeyShare.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "could not validate signing key share")
	}
	if err := publicKeyShares.Validate(cohortConfig); err != nil {
		return errs.WrapVerificationFailed(err, "could not validate public key shares")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	if myAuthKey == nil {
		return errs.NewIsNil("my identity key is nil")
	}
	if !cohortConfig.Participants.Contains(myAuthKey) {
		return errs.NewInvalidArgument("identity key is not in cohort config")
	}
	if len(sessionId) == 0 {
		return errs.NewInvalidArgument("invalid session id: %s", sessionId)
	}
	return nil
}
