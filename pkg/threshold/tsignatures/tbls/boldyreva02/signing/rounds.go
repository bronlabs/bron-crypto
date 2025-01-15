package signing

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/bls"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02"
)

func (c *Cosigner[K, S]) ProducePartialSignature(message []byte) (sig *boldyreva02.PartialSignature[S], err error) {
	// Validation
	if c.Round != 1 {
		return nil, errs.NewRound("Running round %d but cosigner expected round %d", 1, c.Round)
	}
	if len(message) == 0 {
		return nil, errs.NewIsNil("message cannot be nil")
	}

	// step 1.1 and 1.2
	var sigmaPOP_i *bls.Signature[S]
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

	c.Round++
	return &boldyreva02.PartialSignature[S]{
		SigmaI:    sigma_i,
		SigmaPOPI: sigmaPOP_i,
		POP:       pi_i,
	}, nil
}
