package signing

import (
	"github.com/copperexchange/knox-primitives/pkg/base/errs"
	"github.com/copperexchange/knox-primitives/pkg/base/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/signatures/bls"
	"github.com/copperexchange/knox-primitives/pkg/threshold/tsignatures/tbls/boldyreva02"
	"github.com/copperexchange/knox-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/signing/aggregation"
)

func (c *Cosigner[_, S]) ProducePartialSignature(message []byte) (*boldyreva02.PartialSignature[S], error) {
	if c.round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", c.round)
	}
	// step 1.1 and 1.2
	sigma_i, pi_i, err := c.signer.Sign(message)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce partial signature")
	}
	c.round++
	return &boldyreva02.PartialSignature[S]{
		Sigma_i: sigma_i,
		POP:     pi_i,
	}, nil
}

func (c *Cosigner[K, S]) Aggregate(partialSignatures map[helper_types.IdentityHash]*boldyreva02.PartialSignature[S], message []byte) (*bls.Signature[S], error) {
	if c.round != 2 {
		return nil, errs.NewInvalidRound("round mismatch %d != 2", c.round)
	}
	if !c.IsSignatureAggregator() {
		return nil, errs.NewInvalidType("i'm not a signature aggregator")
	}
	aggregator, err := aggregation.NewAggregator[K, S](c.myShard.PublicKeyShares, c.cohortConfig)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct aggregator")
	}
	signature, err := aggregator.Aggregate(partialSignatures, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "aggregation failed")
	}
	return signature, nil
}
