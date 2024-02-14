package aggregation

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dleq"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow"
)

type Aggregator struct {
	publicKeyShares *glow.PublicKeyShares
	protocol        types.ThresholdSignatureProtocol
	sid             []byte
	sharingConfig   types.SharingConfig
}

func NewAggregator(uniqueSessionId []byte, publicKeyShares *glow.PublicKeyShares, protocol types.ThresholdSignatureProtocol) (*Aggregator, error) {
	err := validateInputs(uniqueSessionId, publicKeyShares, protocol)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not validate inputs")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	return &Aggregator{
		sid:             uniqueSessionId,
		publicKeyShares: publicKeyShares,
		protocol:        protocol,
		sharingConfig:   sharingConfig,
	}, nil
}

func validateInputs(uniqueSessionId []byte, publicKeyShares *glow.PublicKeyShares, protocol types.ThresholdSignatureProtocol) error {
	if err := types.ValidateThresholdSignatureProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config")
	}
	if protocol.CipherSuite().Curve().Name() != new(glow.KeySubGroup).Name() {
		return errs.NewArgument("cohort config curve mismatch with the declared subgroup")
	}
	if err := publicKeyShares.Validate(protocol); err != nil {
		return errs.WrapArgument(err, "could not validate public key shares")
	}
	if len(uniqueSessionId) == 0 {
		return errs.NewLength("sid length is zero")
	}
	return nil
}

func (a *Aggregator) Aggregate(partialSignatures types.RoundMessages[*glow.PartialSignature], message []byte) (*bls.Signature[bls12381.G2], error) {
	sharingIds := make([]uint, partialSignatures.Size())
	i := 0
	for pair := range partialSignatures.Iter() {
		sharingId, exists := a.sharingConfig.LookUpRight(pair.Key)
		if !exists {
			return nil, errs.NewMembership("participant %x is not in cohort", pair.Key.PublicKey())
		}
		sharingIds[i] = uint(sharingId)
		i++
	}

	lambdas, err := shamir.LagrangeCoefficients(new(glow.KeySubGroup), sharingIds)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't produce lagrange coefficients for present participants")
	}

	sigma := bls12381.NewG2().Identity()
	Hm, err := bls12381.NewPairingCurve().G2().HashWithDst(message, []byte(bls.DstSignatureBasicInG2))
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't hash message")
	}

	// step 2.1
	for pair := range partialSignatures.Iter() {
		identityKey := pair.Key
		psig := pair.Value
		sharingId, exists := a.sharingConfig.LookUpRight(identityKey)
		if !exists {
			return nil, errs.NewMissing("could not find sharing id of participant %x", identityKey.PublicKey())
		}
		if psig == nil {
			return nil, errs.NewMissing("missing partial signature for %x", identityKey.PublicKey())
		}
		if psig.DleqProof == nil {
			return nil, errs.NewMissing("missing pop for %x", identityKey.PublicKey())
		}
		if psig.SigmaI == nil {
			return nil, errs.NewMissing("missing signature for %x", identityKey.PublicKey())
		}
		publicKeyShare, exists := a.publicKeyShares.Shares.Get(identityKey)
		if !exists {
			return nil, errs.NewMissing("couldn't find public key share of %x", identityKey.PublicKey())
		}

		dleqStatement := &dleq.Statement{
			X1: publicKeyShare,
			X2: psig.SigmaI.Value,
		}
		if err := dleq.Verify(a.sid, psig.DleqProof, dleqStatement, new(glow.KeySubGroup).Generator(), Hm, glow.DleqNIZKCompiler, nil); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, identityKey.PublicKey().ToAffineCompressed(), "could not verify dleq proof")
		}

		lambda_i, exists := lambdas[uint(sharingId)]
		if !exists {
			return nil, errs.NewMissing("couldn't find lagrange coefficient for %x", identityKey.PublicKey())
		}

		// step 2.2 (we'll complete it gradually here to avoid another for loop)
		sigma = sigma.Add(psig.SigmaI.Value.Mul(lambda_i))
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
