package aggregation

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02"
)

type Aggregator[K bls.KeySubGroup, S bls.SignatureSubGroup] struct {
	publicKeyShares        *boldyreva02.PublicKeyShares[K]
	cohortConfig           *integration.CohortConfig
	identityKeyToSharingId map[types.IdentityHash]int
	scheme                 bls.RogueKeyPrevention
}

func NewAggregator[K bls.KeySubGroup, S bls.SignatureSubGroup](publicKeyShares *boldyreva02.PublicKeyShares[K], scheme bls.RogueKeyPrevention, cohortConfig *integration.CohortConfig) (*Aggregator[K, S], error) {
	err := validateInputs[K, S](publicKeyShares, cohortConfig)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not validate inputs")
	}

	if cohortConfig.Protocol == nil {
		return nil, errs.NewIsNil("protocol config is nil")
	}
	if err := publicKeyShares.Validate(cohortConfig); err != nil {
		return nil, errs.WrapInvalidArgument(err, "public key shares are invalid")
	}
	_, identityKeyToSharingId, _ := integration.DeriveSharingIds(nil, cohortConfig.Participants)
	return &Aggregator[K, S]{
		publicKeyShares:        publicKeyShares,
		cohortConfig:           cohortConfig,
		identityKeyToSharingId: identityKeyToSharingId,
		scheme:                 scheme,
	}, nil
}

func validateInputs[K bls.KeySubGroup, S bls.SignatureSubGroup](publicKeyShares *boldyreva02.PublicKeyShares[K], cohortConfig *integration.CohortConfig) error {
	if bls.SameSubGroup[K, S]() {
		return errs.NewInvalidType("key and signature subgroup should not be the same")
	}
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapInvalidArgument(err, "cohort config is invalid")
	}
	if cohortConfig.CipherSuite.Curve.Name() != (*new(K)).CurveName() {
		return errs.NewInvalidArgument("cohort config curve mismatch with the declared subgroup")
	}
	if err := publicKeyShares.Validate(cohortConfig); err != nil {
		return errs.WrapInvalidArgument(err, "could not validate public key shares")
	}
	return nil
}

func (a *Aggregator[K, S]) Aggregate(partialSignatures map[types.IdentityHash]*boldyreva02.PartialSignature[S], message []byte, scheme bls.RogueKeyPrevention) (*bls.Signature[S], *bls.ProofOfPossession[S], error) {
	if bls.SameSubGroup[K, S]() {
		return nil, nil, errs.NewInvalidType("key and signature subgroups can't be the same")
	}
	pointInK := new(K)
	pointInS := new(S)
	keySubGroup := (*pointInK).Curve()
	signatureSubGroup := (*pointInS).Curve()

	presentParticipantsToSharingId := make(map[types.IdentityHash]int, len(partialSignatures))
	sharingIds := make([]int, len(partialSignatures))
	i := 0
	for id := range partialSignatures {
		sharingId, exists := a.identityKeyToSharingId[id]
		if !exists {
			return nil, nil, errs.NewMembership("participant %x is not in cohort", id)
		}
		sharingIds[i] = sharingId
		presentParticipantsToSharingId[id] = sharingId
		i++
	}

	lambdas, err := shamir.LagrangeCoefficients(keySubGroup, sharingIds)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "couldn't produce lagrange coefficients for present participants")
	}

	sigma := signatureSubGroup.Point().Identity()
	sigmaPOP := signatureSubGroup.Point().Identity()

	// step 2.1
	for identityHash, psig := range partialSignatures {
		var internalMessage []byte
		if psig == nil {
			return nil, nil, errs.NewMissing("missing partial signature for %x", identityHash)
		}
		if psig.POP == nil {
			return nil, nil, errs.NewMissing("missing pop for %x", identityHash)
		}
		if psig.SigmaI == nil {
			return nil, nil, errs.NewMissing("missing signature for %x", identityHash)
		}
		publicKeyShare, exists := a.publicKeyShares.SharesMap[identityHash]
		if !exists {
			return nil, nil, errs.NewMissing("couldn't find public key share of %x", identityHash)
		}
		publicKeyShareAsPublicKey := &bls.PublicKey[K]{
			Y: publicKeyShare,
		}
		// step 2.1.1 and 2.1.2
		switch scheme {
		case bls.Basic:
			internalMessage = message
		case bls.MessageAugmentation:
			internalMessage, err = bls.AugmentMessage(message, a.publicKeyShares.PublicKey)
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "could not augment message")
			}
		case bls.POP:
			internalMessage = message
			internalPopMessage, err := a.publicKeyShares.PublicKey.MarshalBinary()
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "could not marshal public key share")
			}
			if err := bls.Verify(publicKeyShareAsPublicKey, psig.SigmaPOPI, internalPopMessage, psig.POP, bls.POP, bls.GetPOPDst(publicKeyShareAsPublicKey.InG1())); err != nil {
				return nil, nil, errs.WrapIdentifiableAbort(err, identityHash, "could not verify partial signature")
			}
		}
		tag, err := bls.GetDst(scheme, publicKeyShareAsPublicKey.InG1())
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not get dst")
		}
		if err := bls.Verify(publicKeyShareAsPublicKey, psig.SigmaI, internalMessage, psig.POP, bls.POP, tag); err != nil {
			return nil, nil, errs.WrapIdentifiableAbort(err, identityHash, "could not verify partial signature")
		}

		lambda_i, exists := lambdas[presentParticipantsToSharingId[identityHash]]
		if !exists {
			return nil, nil, errs.NewMissing("couldn't find lagrange coefficient for %x", identityHash)
		}

		// step 2.2 (we'll complete it gradually here to avoid another for loop)
		sigma = sigma.Add(psig.SigmaI.Value.Mul(lambda_i))
		if psig.SigmaPOPI != nil && scheme == bls.POP {
			sigmaPOP = sigmaPOP.Add(psig.SigmaPOPI.Value.Mul(lambda_i))
		}
	}

	sigmaPairable, ok := sigma.(curves.PairingPoint)
	if !ok {
		return nil, nil, errs.NewInvalidType("sigma couldn't be converted to a pairable point")
	}

	// step 2.3
	if scheme == bls.POP {
		if sigmaPOP == nil || sigmaPOP.IsIdentity() {
			return nil, nil, errs.NewInvalidArgument("sigma POP is nil or identity")
		}
		sigmaPOPPairable, ok := sigmaPOP.(curves.PairingPoint)
		if !ok {
			return nil, nil, errs.NewInvalidType("sigma POP couldn't be converted to a pairable point")
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
