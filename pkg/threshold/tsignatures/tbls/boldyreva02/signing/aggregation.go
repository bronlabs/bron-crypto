package signing

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02"
)

func Aggregate[K bls.KeySubGroup, S bls.SignatureSubGroup](sharingConfig types.SharingConfig, partialPublicKeys *boldyreva02.PartialPublicKeys[K], partialSignatures types.RoundMessages[*boldyreva02.PartialSignature[S]], message []byte, scheme bls.RogueKeyPrevention) (*bls.Signature[S], *bls.ProofOfPossession[S], error) {
	if bls.SameSubGroup[K, S]() {
		return nil, nil, errs.NewType("key and signature subgroups can't be the same")
	}
	keySubGroup := bls12381.GetSourceSubGroup[K]()
	signatureSubGroup := bls12381.GetSourceSubGroup[S]()

	sharingIds := make([]uint, partialSignatures.Size())
	i := 0
	for pair := range partialSignatures.Iter() {
		sharingId, exists := sharingConfig.Reverse().Get(pair.Key)
		if !exists {
			return nil, nil, errs.NewMembership("participant %x is not in cohort", pair.Key.PublicKey())
		}
		sharingIds[i] = uint(sharingId)
		i++
	}

	lambdas, err := shamir.LagrangeCoefficients(keySubGroup, sharingIds)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldn't produce lagrange coefficients for present participants")
	}

	sigma := signatureSubGroup.Identity()
	sigmaPOP := signatureSubGroup.Identity()

	// step 2.1
	for pair := range partialSignatures.Iter() {
		identityKey := pair.Key
		psig := pair.Value
		sharingId, exists := sharingConfig.Reverse().Get(identityKey)
		if !exists {
			return nil, nil, errs.NewMissing("could not find sharing id of participant %x", identityKey.PublicKey())
		}
		var internalMessage []byte
		if psig == nil {
			return nil, nil, errs.NewMissing("missing partial signature for %x", identityKey.PublicKey())
		}
		if psig.POP == nil {
			return nil, nil, errs.NewMissing("missing pop for %x", identityKey.PublicKey())
		}
		if psig.SigmaI == nil {
			return nil, nil, errs.NewMissing("missing signature for %x", identityKey.PublicKey())
		}
		publicKeyShare, exists := partialPublicKeys.Shares.Get(identityKey)
		if !exists {
			return nil, nil, errs.NewMissing("couldn't find public key share of %x", identityKey.PublicKey())
		}
		Y, ok := publicKeyShare.(curves.PairingPoint)
		if !ok {
			return nil, nil, errs.NewType("partial public key of %x is invalid", identityKey.PublicKey())
		}
		publicKeyShareAsPublicKey := &bls.PublicKey[K]{
			Y: Y,
		}
		// step 2.1.1 and 2.1.2
		switch scheme {
		case bls.Basic:
			internalMessage = message
		case bls.MessageAugmentation:
			internalMessage, err = bls.AugmentMessage(message, partialPublicKeys.PublicKey)
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "could not augment message")
			}
		case bls.POP:
			internalMessage = message
			internalPopMessage, err := partialPublicKeys.PublicKey.MarshalBinary()
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "could not marshal public key share")
			}
			if err := bls.Verify(publicKeyShareAsPublicKey, psig.SigmaPOPI, internalPopMessage, psig.POP, bls.POP, bls.GetPOPDst(publicKeyShareAsPublicKey.InG1())); err != nil {
				return nil, nil, errs.WrapIdentifiableAbort(err, identityKey.PublicKey().ToAffineCompressed(), "could not verify partial signature")
			}
		}
		tag, err := bls.GetDst(scheme, publicKeyShareAsPublicKey.InG1())
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not get dst")
		}
		if err := bls.Verify(publicKeyShareAsPublicKey, psig.SigmaI, internalMessage, psig.POP, bls.POP, tag); err != nil {
			return nil, nil, errs.WrapIdentifiableAbort(err, identityKey.PublicKey().ToAffineCompressed(), "could not verify partial signature")
		}

		lambda_i, exists := lambdas[uint(sharingId)]
		if !exists {
			return nil, nil, errs.NewMissing("couldn't find lagrange coefficient for %x", identityKey.PublicKey())
		}

		// step 2.2 (we'll complete it gradually here to avoid another for loop)
		sigma = sigma.Add(psig.SigmaI.Value.Mul(lambda_i))
		if psig.SigmaPOPI != nil && scheme == bls.POP {
			sigmaPOP = sigmaPOP.Add(psig.SigmaPOPI.Value.Mul(lambda_i))
		}
	}

	sigmaPairable, ok := sigma.(curves.PairingPoint)
	if !ok {
		return nil, nil, errs.NewType("sigma couldn't be converted to a pairable point")
	}

	// step 2.3
	if scheme == bls.POP {
		if sigmaPOP == nil || sigmaPOP.IsIdentity() {
			return nil, nil, errs.NewArgument("sigma POP is nil or identity")
		}
		sigmaPOPPairable, ok := sigmaPOP.(curves.PairingPoint)
		if !ok {
			return nil, nil, errs.NewType("sigma POP couldn't be converted to a pairable point")
		}
		return &bls.Signature[S]{
				Value: sigmaPairable,
			}, &bls.ProofOfPossession[S]{
				Value: sigmaPOPPairable,
			}, nil
	} else {
		return &bls.Signature[S]{
			Value: sigmaPairable,
		}, nil, nil
	}
}
