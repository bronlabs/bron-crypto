package aggregation

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/hashing"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/sharing/shamir"
	"github.com/copperexchange/knox-primitives/pkg/signatures/eddsa"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/frost"
)

type SignatureAggregator struct {
	CohortConfig           *integration.CohortConfig
	PublicKey              curves.Point
	MyIdentityKey          integration.IdentityKey
	SessionParticipants    []integration.IdentityKey
	IdentityKeyToSharingId map[integration.IdentityHash]int
	PublicKeyShares        *frost.PublicKeyShares
	Message                []byte

	parameters *SignatureAggregatorParameters
}

func (sa *SignatureAggregator) HasIdentifiableAbort() bool {
	return sa.PublicKeyShares != nil
}

type SignatureAggregatorParameters struct {
	Z_i     curves.Scalar
	R       curves.Point
	R_js    map[integration.IdentityHash]curves.Point
	D_alpha map[integration.IdentityHash]curves.Point
	E_alpha map[integration.IdentityHash]curves.Point
}

func NewSignatureAggregator(identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, shard *frost.Shard, sessionParticipants []integration.IdentityKey, identityKeyToSharingId map[integration.IdentityHash]int, message []byte, parameters *SignatureAggregatorParameters) (*SignatureAggregator, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if !cohortConfig.IsSignatureAggregator(identityKey) {
		return nil, errs.NewInvalidArgument("provided identity key is not a signature aggregator of the given cohort config")
	}
	if sessionParticipants == nil {
		return nil, errs.NewIsNil("must provide the list of the sharing ids of session participants")
	}
	if len(sessionParticipants) == 0 {
		return nil, errs.NewIncorrectCount("must provide the list of the sharing ids of session participants")
	}
	if len(identityKeyToSharingId) != cohortConfig.TotalParties {
		return nil, errs.NewIncorrectCount("don't have enough mapping for shamir to identity keys as we have parties")
	}
	if shard == nil {
		return nil, errs.NewIsNil("shard is nil")
	}
	if shard.PublicKeyShares.PublicKey.IsIdentity() {
		return nil, errs.NewIsIdentity("public key can't be at infinity")
	}
	if !shard.PublicKeyShares.PublicKey.IsOnCurve() {
		return nil, errs.NewNotOnCurve("public key is not on curve")
	}
	if message == nil {
		return nil, errs.NewIsNil("message is empty")
	}
	if len(message) == 0 {
		return nil, errs.NewIsZero("message is empty")
	}
	if parameters == nil {
		return nil, errs.NewIsNil("aggregation parameter is nil")
	}
	aggregator := &SignatureAggregator{
		CohortConfig:           cohortConfig,
		PublicKey:              shard.PublicKeyShares.PublicKey,
		PublicKeyShares:        shard.PublicKeyShares,
		MyIdentityKey:          identityKey,
		SessionParticipants:    sessionParticipants,
		IdentityKeyToSharingId: identityKeyToSharingId,
		Message:                message,
		parameters:             parameters,
	}
	if aggregator.HasIdentifiableAbort() {
		if len(aggregator.parameters.R_js) != len(sessionParticipants) {
			return nil, errs.NewIncorrectCount("identifiable abort is enabled and the size of Rjs and S is not equal.")
		}
	}
	return aggregator, nil
}

// TODO: condense/simplify.
func (sa *SignatureAggregator) Aggregate(partialSignatures map[integration.IdentityHash]*frost.PartialSignature) (*eddsa.Signature, error) {
	if len(sa.parameters.D_alpha) != len(sa.SessionParticipants) {
		return nil, errs.NewIncorrectCount("length of D_alpha is not equal to S")
	}
	if len(sa.parameters.E_alpha) != len(sa.SessionParticipants) {
		return nil, errs.NewIncorrectCount("length of E_alpha is not equal to S")
	}
	// This is for TS-SUF-4 in case aggregator was the one computing the R
	// for identifiable abort, you need R_js
	recomputedR_js := map[integration.IdentityHash]curves.Point{}
	if sa.parameters.R == nil {
		sa.parameters.R = sa.CohortConfig.CipherSuite.Curve.Point.Identity()
		combinedDsAndEs := []byte{}
		for _, presentParty := range sa.SessionParticipants {
			combinedDsAndEs = append(combinedDsAndEs, sa.parameters.D_alpha[presentParty.Hash()].ToAffineCompressed()...)
		}
		for _, presentParty := range sa.SessionParticipants {
			combinedDsAndEs = append(combinedDsAndEs, sa.parameters.E_alpha[presentParty.Hash()].ToAffineCompressed()...)
		}

		for _, jIdentityKey := range sa.SessionParticipants {
			j := sa.IdentityKeyToSharingId[jIdentityKey.Hash()]

			r_j := sa.CohortConfig.CipherSuite.Curve.Scalar.Hash([]byte{byte(j)}, sa.Message, combinedDsAndEs)
			D_j, exists := sa.parameters.D_alpha[jIdentityKey.Hash()]
			if !exists {
				return nil, errs.NewMissing("could not find D_j for j=%d in D_alpha", j)
			}
			E_j, exists := sa.parameters.E_alpha[jIdentityKey.Hash()]
			if !exists {
				return nil, errs.NewMissing("could not find E_j for j=%d in E_alpha", j)
			}

			recomputedR_js[jIdentityKey.Hash()] = D_j.Add(E_j.Mul(r_j))
			sa.parameters.R = sa.parameters.R.Add(recomputedR_js[jIdentityKey.Hash()])
		}
		sa.parameters.R_js = recomputedR_js
	}

	if sa.HasIdentifiableAbort() {
		shamirConfig, err := shamir.NewDealer(sa.CohortConfig.Threshold, sa.CohortConfig.TotalParties, sa.CohortConfig.CipherSuite.Curve)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not initialise shamir config")
		}

		sharingIDs := make([]int, len(sa.SessionParticipants))
		for i, party := range sa.SessionParticipants {
			var ok bool
			sharingIDs[i], ok = sa.IdentityKeyToSharingId[party.Hash()]
			if !ok {
				return nil, errs.NewMissing("could not find sharing id for the party")
			}
		}
		lagrangeCoefficients, err := shamirConfig.LagrangeCoefficients(sharingIDs)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not compute lagrange coefficients")
		}

		c, err := hashing.FiatShamir(
			sa.CohortConfig.CipherSuite,
			sa.parameters.R.ToAffineCompressed(),
			sa.PublicKey.ToAffineCompressed(),
			sa.Message,
		)
		if err != nil {
			return nil, errs.WrapDeserializationFailed(err, "converting hash to c failed")
		}

		for _, jIdentityKey := range sa.SessionParticipants {
			j, exists := sa.IdentityKeyToSharingId[jIdentityKey.Hash()]
			if !exists {
				return nil, errs.NewMissing("could not find the identity key of cosigner with sharing id %d", j)
			}
			Y_j, exists := sa.PublicKeyShares.SharesMap[jIdentityKey.Hash()]
			if !exists {
				return nil, errs.NewMissing("could not find public key share of sharing id %d", j)
			}
			lambda_j, exists := lagrangeCoefficients[j]
			if !exists {
				return nil, errs.NewMissing("could not find lagrange coefficient of sharing id %d", j)
			}

			partialSignature, exists := partialSignatures[jIdentityKey.Hash()]
			if !exists {
				return nil, errs.NewMissing("could not find partial signature from sharing id %d", j)
			}

			R_j, exists := sa.parameters.R_js[jIdentityKey.Hash()]
			if !exists {
				return nil, errs.NewMissing("could not find R_j for j=%d", j)
			}

			z_jG := sa.CohortConfig.CipherSuite.Curve.ScalarBaseMult(partialSignature.Zi)
			cLambda_jY_j := Y_j.Mul(c.Mul(lambda_j))
			rhs := R_j.Add(cLambda_jY_j)

			if !z_jG.Equal(rhs) {
				return nil, errs.NewIdentifiableAbort("participant with sharing id %d is misbehaving", j)
			}
		}
	}

	z := sa.CohortConfig.CipherSuite.Curve.Scalar.Zero()
	for _, partialSignature := range partialSignatures {
		z = z.Add(partialSignature.Zi)
	}

	sigma := &eddsa.Signature{R: sa.parameters.R, Z: z}

	if err := eddsa.Verify(sa.CohortConfig.CipherSuite.Curve, sa.CohortConfig.CipherSuite.Hash, sigma, sa.PublicKey, sa.Message); err != nil {
		return nil, errs.WrapVerificationFailed(err, "could not verify frost signature")
	}
	return sigma, nil
}
