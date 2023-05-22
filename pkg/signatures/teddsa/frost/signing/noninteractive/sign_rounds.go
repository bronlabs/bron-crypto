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
	nic.state.D_i = (*preSignature)[nic.MyShamirId-1].D
	nic.state.E_i = (*preSignature)[nic.MyShamirId-1].E
	partialSignature, err := interactive.Helper_ProducePartialSignature(
		nic,
		nic.SessionParticipants,
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
	if (preSignatureIndex <= nic.LastUsedPreSignatureIndex) && !(nic.IsSignatureAggregator() && nic.LastUsedPreSignatureIndex == preSignatureIndex) {
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

	aggregationParameters := &aggregation.SignatureAggregatorParameters{
		D_alpha: D_alpha,
		E_alpha: E_alpha,
	}
	aggregator, err := aggregation.NewSignatureAggregator(nic.MyIdentityKey, nic.CohortConfig, nic.SigningKeyShare.PublicKey, nil, nic.SessionParticipants, nic.IdentityKeyToShamirId, message, aggregationParameters)
	if err != nil {
		return nil, errors.Wrap(err, "could not initialize signature aggregator")
	}
	signature, err := aggregator.Aggregate(partialSignatures)
	if err != nil {
		return nil, errors.Wrap(err, "could not aggregate partial signatures")
	}
	return signature, nil
}
