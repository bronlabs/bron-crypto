package signing

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/bls12381"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/network"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/bls"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02"
)

func Aggregate[K bls.KeySubGroup, S bls.SignatureSubGroup](sharingConfig types.SharingConfig, partialPublicKeys *boldyreva02.PartialPublicKeys[K], partialSignatures network.RoundMessages[types.ThresholdProtocol, *boldyreva02.PartialSignature[S]], message []byte, scheme bls.RogueKeyPrevention) (*bls.Signature[S], *bls.ProofOfPossession[S], error) {
	// Validation
	if bls.SameSubGroup[K, S]() {
		return nil, nil, errs.NewType("key and signature subgroups can't be the same")
	}
	if err := partialPublicKeys.ValidateWithSharingConfig(sharingConfig); err != nil {
		return nil, nil, errs.WrapValidation(err, "invalid partial public keys")
	}
	quorum := hashset.NewHashableHashSet(partialSignatures.Keys()...)
	if err := network.ValidateMessages(nil, quorum, nil, partialSignatures); err != nil {
		return nil, nil, errs.WrapValidation(err, "invalid partial signatures")
	}

	sharingIds, err := getSharingIds(quorum, sharingConfig)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldn't get sharing ids")
	}
	lambdas, err := shamir.LagrangeCoefficients(bls12381.GetSourceSubGroup[K](), sharingIds)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldn't produce lagrange coefficients for present participants")
	}

	sigma := bls12381.GetSourceSubGroup[S]().AdditiveIdentity()
	sigmaPOP := bls12381.GetSourceSubGroup[S]().AdditiveIdentity()

	// step 2.1
	for identityKey, psig := range partialSignatures.Iter() {
		sharingId, exists := sharingConfig.Reverse().Get(identityKey)
		if !exists {
			return nil, nil, errs.NewMissing("could not find sharing id of participant %s", identityKey.String())
		}
		publicKeyShare, exists := partialPublicKeys.Shares.Get(sharingId)
		if !exists {
			return nil, nil, errs.NewMissing("couldn't find public key share of %s", identityKey.String())
		}
		Y, ok := publicKeyShare.(curves.PairingPoint)
		if !ok {
			return nil, nil, errs.NewType("partial public key of %s is invalid", identityKey.String())
		}
		publicKeyShareAsPublicKey := &bls.PublicKey[K]{
			Y: Y,
		}
		// step 2.1.1 and 2.1.2
		var internalMessage []byte
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
				return nil, nil, errs.WrapIdentifiableAbort(err, identityKey.String(), "could not verify partial signature")
			}
		}
		tag, err := bls.GetDst(scheme, publicKeyShareAsPublicKey.InG1())
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not get dst")
		}
		if err := bls.Verify(publicKeyShareAsPublicKey, psig.SigmaI, internalMessage, psig.POP, bls.POP, tag); err != nil {
			return nil, nil, errs.WrapIdentifiableAbort(err, identityKey.String(), "could not verify partial signature")
		}

		lambda_i, exists := lambdas[uint(sharingId)]
		if !exists {
			return nil, nil, errs.NewMissing("couldn't find lagrange coefficient for %s", identityKey.String())
		}

		// step 2.2 (we'll complete it gradually here to avoid another for loop)
		sigma = sigma.Add(psig.SigmaI.Value.ScalarMul(lambda_i))
		if psig.SigmaPOPI != nil && scheme == bls.POP {
			sigmaPOP = sigmaPOP.Add(psig.SigmaPOPI.Value.ScalarMul(lambda_i))
		}
	}

	sigmaPairable, ok := sigma.(curves.PairingPoint)
	if !ok {
		return nil, nil, errs.NewType("sigma couldn't be converted to a pairable point")
	}

	// step 2.3
	if scheme == bls.POP {
		if sigmaPOP == nil || sigmaPOP.IsAdditiveIdentity() {
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

func getSharingIds(quorum ds.Set[types.IdentityKey], sharingConfig types.SharingConfig) ([]uint, error) {
	sharingIds := make([]uint, quorum.Size())
	for i, signer := range quorum.List() {
		sharingId, exists := sharingConfig.Reverse().Get(signer)
		if !exists {
			return nil, errs.NewMembership("participant %s is not in protocol config", signer.String())
		}
		sharingIds[i] = uint(sharingId)
	}
	return sharingIds, nil
}
