package signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dleq"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow/signing/aggregation"
)

func (c *Cosigner) ProducePartialSignature(message []byte) (*glow.PartialSignature, error) {
	if c.round != 1 {
		return nil, errs.NewRound("round mismatch %d != 1", c.round)
	}
	// step 1.1
	sigma_i, _, err := c.signer.Sign(message, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not produce partial signature")
	}
	// step 1.2
	Hm, err := bls12381.NewPairingCurve().G2().HashWithDst(message, []byte(bls.DstSignatureBasicInG2))
	if err != nil {
		return nil, errs.WrapHashing(err, "could not hash message")
	}
	// TODO: pass transcript
	proof, _, err := dleq.Prove(c.sid, c.signer.PrivateKey.D(), bls12381.NewG1().Generator(), Hm, glow.DleqNIZKCompiler, nil, c.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't produce proof")
	}
	c.round++
	// step 1.3
	return &glow.PartialSignature{
		SigmaI:    sigma_i,
		DleqProof: proof,
	}, nil
}

func (c *Cosigner) Aggregate(partialSignatures types.RoundMessages[*glow.PartialSignature], message []byte) (*bls.Signature[bls12381.G2], error) {
	if c.round != 2 {
		return nil, errs.NewRound("round mismatch %d != 2", c.round)
	}
	aggregator, err := aggregation.NewAggregator(c.sid, c.myShard.PublicKeyShares, c.protocol)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct aggregator")
	}
	signature, err := aggregator.Aggregate(partialSignatures, message)
	if err != nil {
		return nil, errs.WrapFailed(err, "aggregation failed")
	}
	return signature, nil
}
