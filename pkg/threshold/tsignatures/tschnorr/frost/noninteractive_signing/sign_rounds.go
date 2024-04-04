package noninteractive_signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	schnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost/interactive_signing/aggregation"
	signing_helpers "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost/interactive_signing/helpers"
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
		nic.Protocol,
		nic.Quorum,
		nic.Shard.SigningKeyShare,
		d_i, e_i,
		nic.aggregationParameter.D_alpha, nic.aggregationParameter.E_alpha,
		nic.SharingConfig,
		message,
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce partial signature")
	}
	return partialSignature, nil
}

func (nic *Cosigner) Aggregate(message []byte, preSignatureIndex int, partialSignatures network.RoundMessages[types.ThresholdProtocol, *frost.PartialSignature]) (*schnorr.Signature, error) {
	aggregator, err := aggregation.NewSignatureAggregator(nic.MyAuthKey, nic.Protocol, nic.Shard.SigningKeyShare.PublicKey, nic.Shard.PublicKeyShares, nic.Quorum, message, nic.aggregationParameter)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not initialise signature aggregator")
	}
	signature, err := aggregator.Aggregate(partialSignatures)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not aggregate partial signatures")
	}
	return signature, nil
}
