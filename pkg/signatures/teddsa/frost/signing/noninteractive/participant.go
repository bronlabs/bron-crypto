package noninteractive

import (
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	interactive "github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing/interactive"
	"github.com/pkg/errors"
)

var _ frost.Participant = (*NonInteractiveCosigner)(nil)

type NonInteractiveCosigner struct {
	reader io.Reader

	PreSignatures     []*PreSignature
	UsedPreSignatures map[*PreSignature]bool

	MyIdentityKey   integration.IdentityKey
	MyShamirId      int
	SigningKeyShare *frost.SigningKeyShare

	CohortConfig          *integration.CohortConfig
	PublicKeyShares       *frost.PublicKeyShares
	ShamirIdToIdentityKey map[int]integration.IdentityKey
	IdentityKeyToShamirId map[integration.IdentityKey]int

	round int
	state *state
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

type state struct {
	// a map from index of presignature to the corresponding D_alpha
	D_alphas map[int]map[integration.IdentityKey]curves.Point
	// a map from index of presignature to the corresponding E_alpha
	E_alphas map[int]map[integration.IdentityKey]curves.Point

	myPrivateNoncePairs map[int]*PrivateNoncePair

	signing *interactive.State
}

func NewNonInteractiveCosigner(
	identityKey integration.IdentityKey, signingKeyShare *frost.SigningKeyShare, publicKeyShare *frost.PublicKeyShares,
	preSignatures []*PreSignature, usedPreSignatures map[*PreSignature]bool, privateNoncePairs []*PrivateNoncePair,
	cohortConfig *integration.CohortConfig, reader io.Reader,
) (*NonInteractiveCosigner, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errors.Wrap(err, "cohort config is invalid")
	}
	if cohortConfig.PreSignatureComposer == nil {
		return nil, errors.New("no presignature composer is set")
	}
	if err := signingKeyShare.Validate(); err != nil {
		return nil, errors.Wrap(err, "could not validate signing key share")
	}
	if len(usedPreSignatures) > len(preSignatures) {
		return nil, errors.New("used presignatures cannot be more than total presignatures")
	}

	preSignatureHashSet := map[*PreSignature]bool{}
	for _, preSignature := range preSignatures {
		preSignatureHashSet[preSignature] = true
	}
	if len(preSignatureHashSet) != len(preSignatures) {
		return nil, errors.New("found duplicate presignatures")
	}

	shamirIdToIdentityKey, myShamirId, err := frost.DeriveShamirIds(identityKey, cohortConfig.Participants)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't derive shamir ids")
	}
	identityKeyToShamirId := map[integration.IdentityKey]int{}
	for shamirId, identityKey := range shamirIdToIdentityKey {
		identityKeyToShamirId[identityKey] = shamirId
	}

	if privateNoncePairs == nil {
		return nil, errors.New("private nonce pairs  is nil")
	}
	if len(privateNoncePairs) != len(preSignatures) {
		return nil, errors.New("length of presignature private material is not equal to the length of presignatures")
	}

	D_alphas := map[int]map[integration.IdentityKey]curves.Point{}
	E_alphas := map[int]map[integration.IdentityKey]curves.Point{}
	myPrivateNoncePairs := map[int]*PrivateNoncePair{}
	for i, preSignature := range preSignatures {
		privateNoncePair := privateNoncePairs[i]
		if err := preSignature.Validate(cohortConfig); err != nil {
			return nil, errors.Wrapf(err, "could not validate presignature at index %d against the private material", i)
		}
		myContributionD := preSignature.DRowsAttested[myShamirId]
		if !myContributionD.Attestor.PublicKey().Equal(identityKey.PublicKey()) {
			return nil, errors.Errorf("my identity key was not found in the right location within presignature number %d", i)
		}
		if err := myContributionD.Validate(cohortConfig); err != nil {
			return nil, errors.Wrapf(err, "presignature number %d is invalid", i)
		}
		if !myContributionD.Commitment.Equal(cohortConfig.CipherSuite.Curve.ScalarBaseMult(privateNoncePair.D)) {
			return nil, errors.New("point D of the presignature does not match with my d nonce")
		}
		myContributionE := preSignature.ERowsAttested[myShamirId]
		if !myContributionE.Attestor.PublicKey().Equal(identityKey.PublicKey()) {
			return nil, errors.Errorf("my identity key was not found in the right location within presignature number %d", i)
		}
		if err := myContributionE.Validate(cohortConfig); err != nil {
			return nil, errors.Wrapf(err, "presignature number %d is invalid", i)
		}
		if !myContributionE.Commitment.Equal(cohortConfig.CipherSuite.Curve.ScalarBaseMult(privateNoncePair.E)) {
			return nil, errors.New("point D of the presignature does not match with my d nonce")
		}

		D_alpha := map[integration.IdentityKey]curves.Point{}
		E_alpha := map[integration.IdentityKey]curves.Point{}
		if !usedPreSignatures[preSignature] {
			for _, attestedCommitment := range preSignature.DRowsAttested {
				D_alpha[attestedCommitment.Attestor] = attestedCommitment.Commitment
			}
			for _, attestedCommitment := range preSignature.ERowsAttested {
				E_alpha[attestedCommitment.Attestor] = attestedCommitment.Commitment
			}
			myPrivateNoncePairs[i] = privateNoncePair
			D_alphas[i] = D_alpha
			E_alphas[i] = E_alpha
		}
	}

	return &NonInteractiveCosigner{
		reader:                reader,
		PreSignatures:         preSignatures,
		UsedPreSignatures:     usedPreSignatures,
		MyIdentityKey:         identityKey,
		SigningKeyShare:       signingKeyShare,
		CohortConfig:          cohortConfig,
		PublicKeyShares:       publicKeyShare,
		ShamirIdToIdentityKey: shamirIdToIdentityKey,
		IdentityKeyToShamirId: identityKeyToShamirId,
		round:                 1,
		state: &state{
			D_alphas:            D_alphas,
			E_alphas:            E_alphas,
			myPrivateNoncePairs: myPrivateNoncePairs,
			signing:             &interactive.State{},
		},
	}, nil
}
