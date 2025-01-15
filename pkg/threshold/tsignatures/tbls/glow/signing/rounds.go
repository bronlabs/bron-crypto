package signing

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/dleq"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/bls"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tbls/glow"
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
	// Note: the aggregator will run dleq.Verify without transcript, thus we set it to nil here
	proof, _, err := dleq.Prove(c.sessionId, c.signer.PrivateKey.D(), bls12381.NewG1().Generator(), Hm, glow.DleqNIZKCompiler, nil, c.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't produce proof")
	}
	c.round++
	// step 1.3
	return &glow.PartialSignature{
		SigmaI:    sigma_i,
		DleqProof: proof,
		SessionId: c.sessionId,
	}, nil
}
