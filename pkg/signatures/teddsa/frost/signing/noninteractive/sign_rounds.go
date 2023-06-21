package noninteractive

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	signing_helpers "github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/signing/aggregation"
)

func (nic *NonInteractiveCosigner) ProducePartialSignature(message []byte) (*frost.PartialSignature, error) {
	privateNoncePair := nic.myPrivateNoncePairs[nic.FirstUnusedPreSignatureIndex]
	d_i := privateNoncePair.SmallD
	e_i := privateNoncePair.SmallE

	partialSignature, err := signing_helpers.ProducePartialSignature(
		nic,
		nic.SessionParticipants,
		nic.SigningKeyShare,
		d_i, e_i,
		nic.D_alpha, nic.E_alpha,
		nic.ShamirIdToIdentityKey,
		nic.IdentityKeyToShamirId,
		nic.aggregationParameter,
		message,
	)

	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce partial signature")
	}
	return partialSignature, nil
}

func (nic *NonInteractiveCosigner) Aggregate(message []byte, preSignatureIndex int, partialSignatures map[integration.IdentityKey]*frost.PartialSignature) (*frost.Signature, error) {
	nic.aggregationParameter.D_alpha = nic.D_alpha
	nic.aggregationParameter.E_alpha = nic.E_alpha
	aggregator, err := aggregation.NewSignatureAggregator(nic.MyIdentityKey, nic.CohortConfig, nic.SigningKeyShare.PublicKey, nic.PublicKeyShares, nic.SessionParticipants, nic.IdentityKeyToShamirId, message, nic.aggregationParameter)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not initialize signature aggregator")
	}
	signature, err := aggregator.Aggregate(partialSignatures)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not aggregate partial signatures")
	}
	return signature, nil
}
