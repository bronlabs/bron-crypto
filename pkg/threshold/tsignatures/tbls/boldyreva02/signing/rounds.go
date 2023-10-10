package signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/signing/aggregation"
)

func (c *Cosigner[_, S]) ProducePartialSignature(message []byte) (*boldyreva02.PartialSignature[S], error) {
	if c.round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", c.round)
	}
	// step 1.1 and 1.2
	sigma_i, pi_i, err := c.signer.Sign(message, getDst[S]())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce partial signature")
	}
	c.round++
	return &boldyreva02.PartialSignature[S]{
		SigmaI: sigma_i,
		POP:    pi_i,
	}, nil
}

func (c *Cosigner[K, S]) Aggregate(partialSignatures map[types.IdentityHash]*boldyreva02.PartialSignature[S], message []byte) (*bls.Signature[S], error) {
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

// we are overriding the default dst. We want a BASIC scheme with POP dst. Because we are generating and verifying pops,
// but output a signature that does not have a pop.
func getDst[S bls.SignatureSubGroup]() []byte {
	pointInS := new(S)
	if (*pointInS).CurveName() == bls12381.G1Name {
		return []byte(bls.DstSignatureBasicInG1)
	}
	return []byte(bls.DstSignatureBasicInG2)
}
