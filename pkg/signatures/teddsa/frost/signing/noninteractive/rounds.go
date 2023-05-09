package noninteractive

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing/aggregation"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing/interactive"
	"github.com/pkg/errors"
)

func (nic *NonInteractiveCosigner) ProducePartialSignature(message []byte) (*frost.PartialSignature, int, error) {
	preSignatureIndex := nic.LastUsedPreSignatureIndex + 1
	preSignature := (*nic.PreSignatures)[preSignatureIndex]
	D_alpha, exists := nic.D_alphas[preSignatureIndex]
	if !exists {
		return nil, -1, errors.Errorf("could not find D_alpha for index %d", preSignatureIndex)
	}
	E_alpha, exists := nic.E_alphas[preSignatureIndex]
	if !exists {
		return nil, -1, errors.Errorf("could not find E_alpha for index %d", preSignatureIndex)
	}
	privateNoncePair := nic.myPrivateNoncePairs[preSignatureIndex]
	nic.state.SmallD_i = privateNoncePair.SmallD
	nic.state.SmallE_i = privateNoncePair.SmallE
	nic.state.D_i = (*preSignature)[nic.MyShamirId].D
	nic.state.E_i = (*preSignature)[nic.MyShamirId].E
	partialSignature, err := interactive.Helper_ProducePartialSignature(
		nic,
		nic.PresentParties,
		nic.SigningKeyShare,
		D_alpha, E_alpha,
		nic.ShamirIdToIdentityKey,
		nic.IdentityKeyToShamirId,
		nic.state,
		message,
	)
	if err != nil {
		return nil, -1, errors.Wrap(err, "could not produce partial signature")
	}
	nic.LastUsedPreSignatureIndex++
	return partialSignature, preSignatureIndex, nil
}

func (nic *NonInteractiveCosigner) Aggregate(preSignatureIndex int, message []byte, partialSignatures map[integration.IdentityKey]*frost.PartialSignature) (*frost.Signature, error) {
	if preSignatureIndex < 0 || preSignatureIndex >= len(*nic.PreSignatures) {
		return nil, errors.New("pre signature index out of bound")
	}
	if preSignatureIndex <= nic.LastUsedPreSignatureIndex {
		return nil, errors.New("pre signature index is already used")
	}
	D_alpha, exists := nic.D_alphas[preSignatureIndex]
	if !exists {
		return nil, errors.Errorf("could not find D_alpha for index %d", preSignatureIndex)
	}
	E_alpha, exists := nic.E_alphas[preSignatureIndex]
	if !exists {
		return nil, errors.Errorf("could not find E_alpha for index %d", preSignatureIndex)
	}

	presentPartyShamirIds := make([]int, len(nic.PresentParties))
	for i := 0; i < len(nic.PresentParties); i++ {
		presentPartyShamirIds[i] = nic.IdentityKeyToShamirId[nic.PresentParties[i]]
	}

	aggregationParameters := &aggregation.SignatureAggregatorParameters{
		Message: message,
		D_alpha: D_alpha,
		E_alpha: E_alpha,
	}
	aggregator, err := aggregation.NewSignatureAggregator(nic.MyIdentityKey, nic.CohortConfig, nic.SigningKeyShare.PublicKey, nic.PublicKeyShares, presentPartyShamirIds, nic.ShamirIdToIdentityKey, aggregationParameters)
	if err != nil {
		return nil, errors.Wrap(err, "could not initialize signature aggregator")
	}
	signature, err := aggregator.Aggregate(partialSignatures)
	if err != nil {
		return nil, errors.Wrap(err, "could not aggregate partial signatures")
	}
	return signature, nil
}
