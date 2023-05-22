package noninteractive

import (
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing/interactive"
	"github.com/pkg/errors"
)

var _ frost.Participant = (*NonInteractiveCosigner)(nil)

type NonInteractiveCosigner struct {
	reader io.Reader

	PreSignatures             *PreSignatureBatch
	LastUsedPreSignatureIndex int

	MyIdentityKey   integration.IdentityKey
	MyShamirId      int
	SigningKeyShare *frost.SigningKeyShare

	CohortConfig          *integration.CohortConfig
	PublicKeyShares       *frost.PublicKeyShares
	SessionParticipants   []integration.IdentityKey
	ShamirIdToIdentityKey map[int]integration.IdentityKey
	IdentityKeyToShamirId map[integration.IdentityKey]int

	// a map from index of presignature to the corresponding Ds and Es
	D_alphas            map[int]map[integration.IdentityKey]curves.Point
	E_alphas            map[int]map[integration.IdentityKey]curves.Point
	myPrivateNoncePairs []*PrivateNoncePair

	round int
	state *interactive.State
}

func (nic *NonInteractiveCosigner) GetIdentityKey() integration.IdentityKey {
	return nic.MyIdentityKey
}

func (nic *NonInteractiveCosigner) GetShamirId() int {
	return nic.MyShamirId
}

func (nic *NonInteractiveCosigner) GetCohortConfig() *integration.CohortConfig {
	return nic.CohortConfig
}

func (nic *NonInteractiveCosigner) IsSignatureAggregator() bool {
	for _, signatureAggregator := range nic.CohortConfig.SignatureAggregators {
		if signatureAggregator.PublicKey().Equal(nic.MyIdentityKey.PublicKey()) {
			return true
		}
	}
	return false
}

func NewNonInteractiveCosigner(
	identityKey integration.IdentityKey, signingKeyShare *frost.SigningKeyShare, publicKeyShare *frost.PublicKeyShares,
	preSignatureBatch *PreSignatureBatch, lastUsedPresignatureIndex int, privateNoncePairs []*PrivateNoncePair,
	presentParties []integration.IdentityKey, cohortConfig *integration.CohortConfig, reader io.Reader,
) (*NonInteractiveCosigner, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errors.Wrap(err, "cohort config is invalid")
	}
	if err := signingKeyShare.Validate(); err != nil {
		return nil, errors.Wrap(err, "could not validate signing key share")
	}
	if err := preSignatureBatch.Validate(cohortConfig); err != nil {
		return nil, errors.Wrap(err, "presignature batch is invalid")
	}
	if lastUsedPresignatureIndex < 0 || lastUsedPresignatureIndex >= len(*preSignatureBatch) {
		return nil, errors.New("last used presignature index is out of bound")
	}

	shamirIdToIdentityKey, identityKeyToShamirId, myShamirId, err := frost.DeriveShamirIds(identityKey, cohortConfig.Participants)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't derive shamir ids")
	}

	presentPartiesHashSet := map[integration.IdentityKey]bool{}
	for _, participant := range presentParties {
		if presentPartiesHashSet[participant] {
			return nil, errors.New("found duplicate present party")
		}
		presentPartiesHashSet[participant] = true

		if !cohortConfig.IsInCohort(participant) {
			return nil, errors.New("present party is not in cohort")
		}
	}
	if len(presentPartiesHashSet) <= 0 {
		return nil, errors.New("no party is present")
	}

	if privateNoncePairs == nil {
		return nil, errors.New("private nonce pairs  is nil")
	}
	if len(privateNoncePairs) != len(*preSignatureBatch) {
		return nil, errors.New("number of provided private nonce pairs is not equal to total presignatures")
	}
	for i, privateNoncePair := range privateNoncePairs {
		preSignature := (*preSignatureBatch)[i]
		myAttestedCommitment := (*preSignature)[myShamirId-1]
		curve, err := curves.GetCurveByName(myAttestedCommitment.D.CurveName())
		if err != nil {
			return nil, errors.WithStack(err)
		}
		if !curve.ScalarBaseMult(privateNoncePair.SmallD).Equal(myAttestedCommitment.D) {
			return nil, errors.Errorf("my d nonce at index %d is not equal to the corresponding commitment", i)
		}
		if !curve.ScalarBaseMult(privateNoncePair.SmallE).Equal(myAttestedCommitment.E) {
			return nil, errors.Errorf("my e nonce at index %d is not equal to the corresponding commitment", i)
		}
	}

	D_alphas := map[int]map[integration.IdentityKey]curves.Point{}
	E_alphas := map[int]map[integration.IdentityKey]curves.Point{}
	for i := lastUsedPresignatureIndex; i < len(*preSignatureBatch); i++ {
		D_alpha := map[integration.IdentityKey]curves.Point{}
		E_alpha := map[integration.IdentityKey]curves.Point{}
		preSignature := (*preSignatureBatch)[i]
		for _, attestedCommitment := range *preSignature {
			if !presentPartiesHashSet[attestedCommitment.Attestor] {
				continue
			}
			D_alpha[attestedCommitment.Attestor] = attestedCommitment.D
			E_alpha[attestedCommitment.Attestor] = attestedCommitment.E
		}
		D_alphas[i] = D_alpha
		E_alphas[i] = E_alpha
	}

	return &NonInteractiveCosigner{
		reader:                    reader,
		PreSignatures:             preSignatureBatch,
		LastUsedPreSignatureIndex: lastUsedPresignatureIndex,
		MyIdentityKey:             identityKey,
		MyShamirId:                myShamirId,
		SigningKeyShare:           signingKeyShare,
		CohortConfig:              cohortConfig,
		PublicKeyShares:           publicKeyShare,
		ShamirIdToIdentityKey:     shamirIdToIdentityKey,
		IdentityKeyToShamirId:     identityKeyToShamirId,
		SessionParticipants:       presentParties,
		D_alphas:                  D_alphas,
		E_alphas:                  E_alphas,
		myPrivateNoncePairs:       privateNoncePairs,
		round:                     1,
		state:                     &interactive.State{},
	}, nil
}
