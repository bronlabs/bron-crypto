package aggregation

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/sharing"
	"github.com/copperexchange/knox-primitives/pkg/signatures/bls"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tbls/boldyreva02"
)

type Aggregator[K bls.KeySubGroup, S bls.SignatureSubGroup] struct {
	publicKeyShares        *boldyreva02.PublicKeyShares[K]
	cohortConfig           *integration.CohortConfig
	identityKeyToSharingId map[helper_types.IdentityHash]int
}

func NewAggregator[K bls.KeySubGroup, S bls.SignatureSubGroup](publicKeyShares *boldyreva02.PublicKeyShares[K], cohortConfig *integration.CohortConfig) (*Aggregator[K, S], error) {
	if bls.SameSubGroup[K, S]() {
		return nil, errs.NewInvalidType("key and signature subgroup should not be the same")
	}
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapInvalidArgument(err, "cohort config is invalid")
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
	}, nil
}

func (a *Aggregator[K, S]) Aggregate(partialSignatures map[helper_types.IdentityHash]*boldyreva02.PartialSignature[S], message []byte) (*bls.Signature[S], error) {
	if bls.SameSubGroup[K, S]() {
		return nil, errs.NewInvalidType("key and signature subgroups can't be the same")
	}
	pointInK := new(K)
	pointInS := new(S)
	keySubGroup := (*pointInK).Curve()
	signatureSubGroup := (*pointInS).Curve()

	presentParticipantsToSharingId := make(map[helper_types.IdentityHash]int, len(partialSignatures))
	sharingIds := make([]int, len(partialSignatures))
	i := 0
	for id := range partialSignatures {
		sharingId, exists := a.identityKeyToSharingId[id]
		if !exists {
			return nil, errs.NewMembershipError("participant %x is not in cohort", id)
		}
		sharingIds[i] = sharingId
		presentParticipantsToSharingId[id] = sharingId
		i++
	}

	lambdas, err := sharing.LagrangeCoefficients(keySubGroup, sharingIds)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't produce lagrange coefficients for present participants")
	}

	sigma := signatureSubGroup.Point().Identity()

	// step 2. 1
	for identityHash, psig := range partialSignatures {
		if psig == nil {
			return nil, errs.NewMissing("missing partial signature for %x", identityHash)
		}
		if psig.POP == nil {
			return nil, errs.NewMissing("missing pop for %x", identityHash)
		}
		if psig.Sigma_i == nil {
			return nil, errs.NewMissing("missing signature for %x", identityHash)
		}
		publicKeyShare, exists := a.publicKeyShares.SharesMap[identityHash]
		if !exists {
			return nil, errs.NewMissing("couldn't find public key share of %x", identityHash)
		}
		publicKeyShareAsPublicKey := &bls.PublicKey[K]{
			Y: publicKeyShare,
		}
		// step 2.1.1 and 2.1.2
		if err := bls.Verify(publicKeyShareAsPublicKey, psig.Sigma_i, message, psig.POP, bls.POP); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, identityHash, "could not verify partial signature")
		}

		lambda_i, exists := lambdas[presentParticipantsToSharingId[identityHash]]
		if !exists {
			return nil, errs.NewMissing("couldn't find lagrange coefficient for %x", identityHash)
		}

		// step 2.2 (we'll complete it gradually here to avoid another for loop)
		sigma = sigma.Add(psig.Sigma_i.Value.Mul(lambda_i))
	}

	sigmaPairable, ok := sigma.(curves.PairingPoint)
	if !ok {
		return nil, errs.NewInvalidType("sigma couldn't be converted to a pairable point")
	}

	// step 2.3
	return &bls.Signature[S]{
		Value: sigmaPairable,
	}, nil
}
