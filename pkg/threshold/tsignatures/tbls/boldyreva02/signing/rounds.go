package signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/signing/aggregation"
)

func (c *Cosigner[K, S]) ProducePartialSignature(message []byte) (*boldyreva02.PartialSignature[S], error) {
	if c.round != 1 {
		return nil, errs.NewRound("round mismatch %d != 1", c.round)
	}
	var err error
	var sigmaPOP_i *bls.Signature[S]
	// step 1.1 and 1.2
	switch c.scheme {
	case bls.Basic:
	case bls.MessageAugmentation:
		message, err = bls.AugmentMessage[K](message, c.myShard.PublicKeyShares.PublicKey)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not augment message")
		}
	case bls.POP:
		msg, err := c.myShard.PublicKeyShares.PublicKey.MarshalBinary()
		if err != nil {
			return nil, errs.WrapFailed(err, "could not marshal public key")
		}
		sigmaPOP_i, _, err = c.signer.Sign(msg, bls.GetPOPDst(c.myShard.PublicKeyShares.PublicKey.InG1()))
		if err != nil {
			return nil, errs.WrapFailed(err, "could not produce POP partial signature")
		}
	default:
		return nil, errs.NewType("scheme type %v not implemented", c.scheme)
	}
	tag, err := bls.GetDst(c.scheme, c.myShard.PublicKeyShares.PublicKey.InG1())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not get dst")
	}
	sigma_i, pi_i, err := c.signer.Sign(message, tag)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce partial signature")
	}
	c.round++
	return &boldyreva02.PartialSignature[S]{
		SigmaI:    sigma_i,
		SigmaPOPI: sigmaPOP_i,
		POP:       pi_i,
	}, nil
}

func (c *Cosigner[K, S]) Aggregate(partialSignatures types.RoundMessages[*boldyreva02.PartialSignature[S]], message []byte, scheme bls.RogueKeyPrevention) (*bls.Signature[S], *bls.ProofOfPossession[S], error) {
	if c.round != 2 {
		return nil, nil, errs.NewRound("round mismatch %d != 2", c.round)
	}
	if !c.IsSignatureAggregator() {
		return nil, nil, errs.NewType("i'm not a signature aggregator")
	}
	aggregator, err := aggregation.NewAggregator[K, S](c.myShard.PublicKeyShares, scheme, c.protocol)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not construct aggregator")
	}
	signature, signaturePOP, err := aggregator.Aggregate(partialSignatures, message, scheme)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "aggregation failed")
	}
	return signature, signaturePOP, nil
}
