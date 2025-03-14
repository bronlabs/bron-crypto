package signing

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dleq"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tbls/glow"
)

func Aggregate(publicKeyShares *glow.PublicKeyShares, protocol types.ThresholdSignatureProtocol, partialSignatures network.RoundMessages[types.ThresholdProtocol, *glow.PartialSignature], message []byte) (*bls.Signature[bls12381.G2], error) {
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())

	if err := validateAggregatorInputs(publicKeyShares, protocol); err != nil {
		return nil, errs.WrapFailed(err, "could not validate inputs")
	}
	sharingIds := make([]uint, partialSignatures.Size())
	i := 0
	for key := range partialSignatures.Iter() {
		sharingId, exists := sharingConfig.Reverse().Get(key)
		if !exists {
			return nil, errs.NewMembership("participant %s is not in protocol config", key.String())
		}
		sharingIds[i] = uint(sharingId)
		i++
	}

	lambdas, err := shamir.LagrangeCoefficients(new(glow.KeySubGroup), sharingIds)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't produce lagrange coefficients for present participants")
	}

	sigma := bls12381.NewG2().AdditiveIdentity()
	Hm, err := bls12381.NewPairingCurve().G2().HashWithDst(message, []byte(bls.DstSignatureBasicInG2))
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't hash message")
	}

	// step 2.1
	for identityKey, psig := range partialSignatures.Iter() {
		sharingId, exists := sharingConfig.Reverse().Get(identityKey)
		if !exists {
			return nil, errs.NewMissing("could not find sharing id of participant %s", identityKey.String())
		}
		if psig == nil {
			return nil, errs.NewMissing("missing partial signature for %s", identityKey.String())
		}
		if psig.DleqProof == nil {
			return nil, errs.NewMissing("missing pop for %s", identityKey.String())
		}
		if psig.SigmaI == nil {
			return nil, errs.NewMissing("missing signature for %s", identityKey.String())
		}
		publicKeyShare, exists := publicKeyShares.Shares.Get(sharingId)
		if !exists {
			return nil, errs.NewMissing("couldn't find public key share of %s", identityKey.String())
		}

		dleqStatement := &dleq.Statement{
			X1: publicKeyShare,
			X2: psig.SigmaI.Value,
		}
		if err := dleq.Verify(psig.SessionId, psig.DleqProof, dleqStatement, new(glow.KeySubGroup).Generator(), Hm, glow.DleqNIZKCompiler, nil); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, identityKey.String(), "could not verify dleq proof")
		}

		lambda_i, exists := lambdas[uint(sharingId)]
		if !exists {
			return nil, errs.NewMissing("couldn't find lagrange coefficient for %s", identityKey.String())
		}

		// step 2.2 (we'll complete it gradually here to avoid another for loop)
		sigma = sigma.Add(psig.SigmaI.Value.ScalarMul(lambda_i))
	}

	sigmaPairable, ok := sigma.(curves.PairingPoint)
	if !ok {
		return nil, errs.NewType("sigma couldn't be converted to a pairable point")
	}

	// step 2.3
	return &bls.Signature[glow.SignatureSubGroup]{
		Value: sigmaPairable,
	}, nil
}

func validateAggregatorInputs(publicKeyShares *glow.PublicKeyShares, protocol types.ThresholdSignatureProtocol) error {
	if err := types.ValidateThresholdSignatureProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config")
	}
	if protocol.SigningSuite().Curve().Name() != new(glow.KeySubGroup).Name() {
		return errs.NewArgument("protocol config curve mismatch with the declared subgroup")
	}
	if err := publicKeyShares.Validate(protocol); err != nil {
		return errs.WrapArgument(err, "could not validate public key shares")
	}
	return nil
}
