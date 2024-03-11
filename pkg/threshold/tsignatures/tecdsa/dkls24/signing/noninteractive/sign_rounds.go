package noninteractive

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24/signing"
)

func (c *Cosigner) ProducePartialSignature(message []byte) (*dkls24.PartialSignature, error) {
	myAdditiveShare, err := c.Shard().SigningKeyShare.ToAdditive(c.IdentityKey(), c.ppm.PreSigners, c.Protocol())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert my shamir share to additive share")
	}
	blindedAdditiveShare := myAdditiveShare.Add(c.ppm.PrivateMaterial.Zeta)

	partialSignature, err := signing.DoRound3Epilogue(
		&c.Participant,
		c.Protocol(),
		c.ppm.PreSigners,
		message,
		c.ppm.PrivateMaterial.R,
		blindedAdditiveShare,
		c.ppm.PrivateMaterial.Phi,
		c.ppm.PrivateMaterial.Cu,
		c.ppm.PrivateMaterial.Cv,
		c.ppm.PrivateMaterial.Du,
		c.ppm.PrivateMaterial.Dv,
		c.ppm.PrivateMaterial.Psi,
		c.ppm.PreSignature,
	)
	if err != nil {
		return nil, errs.Forward(err)
	}

	return partialSignature, nil
}
