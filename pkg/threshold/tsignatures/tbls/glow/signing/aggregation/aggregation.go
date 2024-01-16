package aggregation

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dleq/chaum"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/glow"
)

type Aggregator struct {
	publicKeyShares        *glow.PublicKeyShares
	cohortConfig           *integration.CohortConfig
	sid                    []byte
	identityKeyToSharingId map[types.IdentityHash]int
}

func NewAggregator(uniqueSessionId []byte, publicKeyShares *glow.PublicKeyShares, cohortConfig *integration.CohortConfig) (*Aggregator, error) {
	err := validateInputs(uniqueSessionId, publicKeyShares, cohortConfig)
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
	return &Aggregator{
		sid:                    uniqueSessionId,
		publicKeyShares:        publicKeyShares,
		cohortConfig:           cohortConfig,
		identityKeyToSharingId: identityKeyToSharingId,
	}, nil
}

func validateInputs(uniqueSessionId []byte, publicKeyShares *glow.PublicKeyShares, cohortConfig *integration.CohortConfig) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapInvalidArgument(err, "cohort config is invalid")
	}
	if err := publicKeyShares.Validate(cohortConfig); err != nil {
		return errs.WrapInvalidArgument(err, "could not validate public key shares")
	}
	if len(uniqueSessionId) == 0 {
		return errs.NewInvalidLength("sid length is zero")
	}
	return nil
}

func (a *Aggregator) Aggregate(partialSignatures map[types.IdentityHash]*glow.PartialSignature, message []byte) (*bls.Signature[bls12381.G2], error) {
	presentParticipantsToSharingId := make(map[types.IdentityHash]int, len(partialSignatures))
	sharingIds := make([]int, len(partialSignatures))
	i := 0
	for id := range partialSignatures {
		sharingId, exists := a.identityKeyToSharingId[id]
		if !exists {
			return nil, errs.NewMembership("participant %x is not in cohort", id)
		}
		sharingIds[i] = sharingId
		presentParticipantsToSharingId[id] = sharingId
		i++
	}

	lambdas, err := shamir.LagrangeCoefficients(bls12381.NewG1(), sharingIds)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't produce lagrange coefficients for present participants")
	}

	sigma := bls12381.NewG2().Identity()
	Hm, err := bls12381.NewPairingCurve().G2().HashWithDst(message, []byte(bls.DstSignatureBasicInG2))
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "couldn't hash message")
	}

	// step 2.1
	for identityHash, psig := range partialSignatures {
		if psig == nil {
			return nil, errs.NewMissing("missing partial signature for %x", identityHash)
		}

		if psig.DleqProof == nil {
			return nil, errs.NewMissing("missing pop for %x", identityHash)
		}
		if psig.SigmaI == nil {
			return nil, errs.NewMissing("missing signature for %x", identityHash)
		}
		publicKeyShare, exists := a.publicKeyShares.SharesMap[identityHash]
		if !exists {
			return nil, errs.NewMissing("couldn't find public key share of %x", identityHash)
		}

		dleqStatement := &chaum.Statement{
			H1: bls12381.NewG1().Generator(),
			H2: Hm,
			P1: publicKeyShare,
			P2: psig.SigmaI.Value,
		}
		if err := chaum.Verify(dleqStatement, psig.DleqProof, a.sid, nil); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, identityHash, "could not verify dleq proof")
		}

		lambda_i, exists := lambdas[presentParticipantsToSharingId[identityHash]]
		if !exists {
			return nil, errs.NewMissing("couldn't find lagrange coefficient for %x", identityHash)
		}

		// step 2.2 (we'll complete it gradually here to avoid another for loop)
		sigma = sigma.Add(psig.SigmaI.Value.Mul(lambda_i))
	}

	sigmaPairable, ok := sigma.(curves.PairingPoint)
	if !ok {
		return nil, errs.NewInvalidType("sigma couldn't be converted to a pairable point")
	}

	// step 2.3
	return &bls.Signature[glow.SignatureSubGroup]{
		Value: sigmaPairable,
	}, nil
}
