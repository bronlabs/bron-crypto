package noninteractive

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	signing_helpers "github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing/aggregation"
	"github.com/pkg/errors"
)

func (nic *NonInteractiveCosigner) ProducePartialSignature(message []byte) (*frost.PartialSignature, error) {
	D_alpha, exists := nic.D_alphas[nic.FirstUnusedPreSignatureIndex]
	if !exists {
		return nil, errors.Errorf("could not find D_alpha for index %d", nic.FirstUnusedPreSignatureIndex)
	}
	E_alpha, exists := nic.E_alphas[nic.FirstUnusedPreSignatureIndex]
	if !exists {
		return nil, errors.Errorf("could not find E_alpha for index %d", nic.FirstUnusedPreSignatureIndex)
	}
	privateNoncePair := nic.myPrivateNoncePairs[nic.FirstUnusedPreSignatureIndex]
	d_i := privateNoncePair.SmallD
	e_i := privateNoncePair.SmallE

	partialSignature, err := signing_helpers.ProducePartialSignature(
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
		return nil, errors.Wrap(err, "could not produce partial signature")
	}
	nic.FirstUnusedPreSignatureIndex++
	return partialSignature, nil
}

func (nic *NonInteractiveCosigner) Aggregate(message []byte, preSignatureIndex int, partialSignatures map[integration.IdentityKey]*frost.PartialSignature) (*frost.Signature, error) {
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
