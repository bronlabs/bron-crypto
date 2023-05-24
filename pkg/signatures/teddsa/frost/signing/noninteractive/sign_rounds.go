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
	D_alpha, exists := nic.D_alphas[preSignatureIndex]
	if !exists {
		return nil, -1, errors.Errorf("could not find D_alpha for index %d", preSignatureIndex)
	}
	E_alpha, exists := nic.E_alphas[preSignatureIndex]
	if !exists {
		return nil, -1, errors.Errorf("could not find E_alpha for index %d", preSignatureIndex)
	}
	privateNoncePair := nic.myPrivateNoncePairs[preSignatureIndex]
	d_i := privateNoncePair.SmallD
	e_i := privateNoncePair.SmallE

	partialSignature, err := interactive.Helper_ProducePartialSignature(
		nic,
		nic.SessionParticipants,
		nic.SigningKeyShare,
		d_i, e_i,
		D_alpha, E_alpha,
		nic.ShamirIdToIdentityKey,
		nic.IdentityKeyToShamirId,
		nic.aggregationParameter,
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

	nic.aggregationParameter.D_alpha = D_alpha
	nic.aggregationParameter.E_alpha = E_alpha
	aggregator, err := aggregation.NewSignatureAggregator(nic.MyIdentityKey, nic.CohortConfig, nic.SigningKeyShare.PublicKey, nic.PublicKeyShares, nic.SessionParticipants, nic.IdentityKeyToShamirId, message, nic.aggregationParameter)
	if err != nil {
		return nil, errors.Wrap(err, "could not initialize signature aggregator")
	}
	signature, err := aggregator.Aggregate(partialSignatures)
	if err != nil {
		return nil, errors.Wrap(err, "could not aggregate partial signatures")
	}
	return signature, nil
}
