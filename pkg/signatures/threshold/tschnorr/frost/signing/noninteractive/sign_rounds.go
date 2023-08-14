package noninteractive

import (
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/signatures/eddsa"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/frost"
	signing_helpers "github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/frost/signing"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/frost/signing/aggregation"
)

func (nic *Cosigner) ProducePartialSignature(message []byte) (*frost.PartialSignature, error) {
	if message == nil {
		return nil, errs.NewIsNil("message is empty")
	}
	if len(message) == 0 {
		return nil, errs.NewIsZero("message is empty")
	}

	privateNoncePair := nic.myPrivateNoncePairs[nic.FirstUnusedPreSignatureIndex]
	d_i := privateNoncePair.SmallD
	e_i := privateNoncePair.SmallE

	partialSignature, err := signing_helpers.ProducePartialSignature(
		nic,
		nic.SessionParticipants,
		nic.Shard.SigningKeyShare,
		d_i, e_i,
		nic.aggregationParameter.D_alpha, nic.aggregationParameter.E_alpha,
		nic.SharingIdToIdentityKey,
		nic.IdentityKeyToSharingId,
		nic.aggregationParameter,
		message,
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce partial signature")
	}
	return partialSignature, nil
}

func (nic *Cosigner) Aggregate(message []byte, preSignatureIndex int, partialSignatures map[integration.IdentityHash]*frost.PartialSignature) (*eddsa.Signature, error) {
	aggregator, err := aggregation.NewSignatureAggregator(nic.MyIdentityKey, nic.CohortConfig, nic.Shard, nic.SessionParticipants, nic.IdentityKeyToSharingId, message, nic.aggregationParameter)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not initialise signature aggregator")
	}
	signature, err := aggregator.Aggregate(partialSignatures)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not aggregate partial signatures")
	}
	return signature, nil
}
