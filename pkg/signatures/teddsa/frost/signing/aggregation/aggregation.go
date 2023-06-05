package aggregation

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/error_types"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	"github.com/copperexchange/crypto-primitives-go/pkg/zkp/schnorr"
	"github.com/pkg/errors"
)

type SignatureAggregator struct {
	CohortConfig          *integration.CohortConfig
	PublicKey             curves.Point
	MyIdentityKey         integration.IdentityKey
	SessionParticipants   []integration.IdentityKey
	IdentityKeyToShamirId map[integration.IdentityKey]int
	PublicKeyShares       *frost.PublicKeyShares
	Message               []byte

	parameters *SignatureAggregatorParameters
}

func (sa *SignatureAggregator) HasIdentifiableAbort() bool {
	return sa.PublicKeyShares != nil
}

type SignatureAggregatorParameters struct {
	Z_i     curves.Scalar
	R       curves.Point
	R_js    map[integration.IdentityKey]curves.Point
	D_alpha map[integration.IdentityKey]curves.Point
	E_alpha map[integration.IdentityKey]curves.Point
}

func NewSignatureAggregator(identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, publicKey curves.Point, publicKeyShares *frost.PublicKeyShares, sessionParticipants []integration.IdentityKey, identityKeyToShamirId map[integration.IdentityKey]int, message []byte, parameters *SignatureAggregatorParameters) (*SignatureAggregator, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errors.Wrapf(err, "%s cohort config is invalid", error_types.EVerificationFailed)
	}
	if !cohortConfig.IsSignatureAggregator(identityKey) {
		return nil, errors.Errorf("%s provided identity key is not a signature aggregator of the given cohort config", error_types.EInvalidArgument)
	}
	if sessionParticipants == nil {
		return nil, errors.Errorf("%s must provide the list of the shamir ids of session participants", error_types.EIsNil)
	}
	if len(sessionParticipants) == 0 {
		return nil, errors.Errorf("%s must provide the list of the shamir ids of session participants", error_types.EIncorrectCount)
	}
	if len(identityKeyToShamirId) != cohortConfig.TotalParties {
		return nil, errors.Errorf("%s don't have enough mapping for shamir to identity keys as we have parties", error_types.EIncorrectCount)
	}
	if publicKey.IsIdentity() {
		return nil, errors.Errorf("%s public key can't be at infinity", error_types.EIsIdentity)
	}
	if !publicKey.IsOnCurve() {
		return nil, errors.Errorf("%s public key is not on curve", error_types.ENotOnCurve)
	}
	if message == nil {
		return nil, errors.Errorf("%s message is empty", error_types.EIsNil)
	}
	if len(message) == 0 {
		return nil, errors.Errorf("%s message is empty", error_types.EIsZero)
	}
	if parameters == nil {
		return nil, errors.Errorf("%s aggregation parameter is nil", error_types.EIsNil)
	}
	aggregator := &SignatureAggregator{
		CohortConfig:          cohortConfig,
		PublicKey:             publicKey,
		PublicKeyShares:       publicKeyShares,
		MyIdentityKey:         identityKey,
		SessionParticipants:   sessionParticipants,
		IdentityKeyToShamirId: identityKeyToShamirId,
		Message:               message,
		parameters:            parameters,
	}
	if aggregator.HasIdentifiableAbort() {
		if len(aggregator.parameters.R_js) != len(sessionParticipants) {
			return nil, errors.Errorf("%s identifiable abort is enabled and the size of Rjs and S is not equal.", error_types.EIncorrectCount)
		}
	}
	return aggregator, nil
}

// TODO: condense/simplify
func (sa *SignatureAggregator) Aggregate(partialSignatures map[integration.IdentityKey]*frost.PartialSignature) (*frost.Signature, error) {
	if len(sa.parameters.D_alpha) != len(sa.SessionParticipants) {
		return nil, errors.Errorf("%s length of D_alpha is not equal to S", error_types.EIncorrectCount)
	}
	if len(sa.parameters.E_alpha) != len(sa.SessionParticipants) {
		return nil, errors.Errorf("%s length of E_alpha is not equal to S", error_types.EIncorrectCount)
	}
	// This is for TS-SUF-4 in case aggregator was the one computing the R
	// for identifiable abort, you need R_js
	recomputedR_js := map[integration.IdentityKey]curves.Point{}
	if sa.parameters.R == nil {
		sa.parameters.R = sa.CohortConfig.CipherSuite.Curve.Point.Identity()
		combinedDsAndEs := []byte{}
		for _, presentParty := range sa.SessionParticipants {
			combinedDsAndEs = append(combinedDsAndEs, sa.parameters.D_alpha[presentParty].ToAffineCompressed()...)
		}
		for _, presentParty := range sa.SessionParticipants {
			combinedDsAndEs = append(combinedDsAndEs, sa.parameters.E_alpha[presentParty].ToAffineCompressed()...)
		}

		for _, jIdentityKey := range sa.SessionParticipants {
			j := sa.IdentityKeyToShamirId[jIdentityKey]
			r_jHashComponents := []byte{byte(j)}
			r_jHashComponents = append(r_jHashComponents, sa.Message...)
			r_jHashComponents = append(r_jHashComponents, combinedDsAndEs...)

			r_j := sa.CohortConfig.CipherSuite.Curve.Scalar.Hash(r_jHashComponents)
			D_j, exists := sa.parameters.D_alpha[jIdentityKey]
			if !exists {
				return nil, errors.Errorf("%s could not find D_j for j=%d in D_alpha", error_types.EMissing, j)
			}
			E_j, exists := sa.parameters.E_alpha[jIdentityKey]
			if !exists {
				return nil, errors.Errorf("%s could not find E_j for j=%d in E_alpha", error_types.EMissing, j)
			}

			recomputedR_js[jIdentityKey] = D_j.Add(E_j.Mul(r_j))
			sa.parameters.R = sa.parameters.R.Add(recomputedR_js[jIdentityKey])
		}
		sa.parameters.R_js = recomputedR_js
	}

	if sa.HasIdentifiableAbort() {
		shamirConfig, err := sharing.NewShamir(sa.CohortConfig.Threshold, sa.CohortConfig.TotalParties, sa.CohortConfig.CipherSuite.Curve)
		if err != nil {
			return nil, errors.Wrapf(err, "%s could not initialize shamir config", error_types.EAbort)
		}

		shamirIDs := make([]int, len(sa.SessionParticipants))
		for i, party := range sa.SessionParticipants {
			var ok bool
			shamirIDs[i], ok = sa.IdentityKeyToShamirId[party]
			if !ok {
				return nil, errors.Errorf("%s could not find shamir id for the party", error_types.EMissing)
			}
		}
		lagrangeCoefficients, err := shamirConfig.LagrangeCoeffs(shamirIDs)
		if err != nil {
			return nil, errors.Wrapf(err, "%s could not compute lagrange coefficients", error_types.EAbort)
		}

		c, err := schnorr.ComputeFiatShamirChallege(sa.CohortConfig.CipherSuite, [][]byte{
			sa.parameters.R.ToAffineCompressed(), sa.PublicKey.ToAffineCompressed(), sa.Message,
		})
		if err != nil {
			return nil, errors.Wrapf(err, "%s converting hash to c failed", error_types.EDeserializationFailed)
		}

		for _, jIdentityKey := range sa.SessionParticipants {
			j, exists := sa.IdentityKeyToShamirId[jIdentityKey]
			if !exists {
				return nil, errors.Errorf("%s could not find the identity key of cosigner with shamir id %d", error_types.EMissing, j)
			}
			Y_j, exists := sa.PublicKeyShares.SharesMap[jIdentityKey]
			if !exists {
				return nil, errors.Errorf("%s could not find public key share of shamir id %d", error_types.EMissing, j)
			}
			lambda_j, exists := lagrangeCoefficients[j]
			if !exists {
				return nil, errors.Errorf("%s could not find lagrange coefficient of shamir id %d", error_types.EMissing, j)
			}

			partialSignature, exists := partialSignatures[jIdentityKey]
			if !exists {
				return nil, errors.Errorf("%s could not find partial signature from shamir id %d", error_types.EMissing, j)
			}

			R_j, exists := sa.parameters.R_js[jIdentityKey]
			if !exists {
				return nil, errors.Errorf("%s could not find R_j for j=%d", error_types.EMissing, j)
			}

			z_jG := sa.CohortConfig.CipherSuite.Curve.ScalarBaseMult(partialSignature.Zi)
			cLambda_jY_j := Y_j.Mul(c.Mul(lambda_j))
			rhs := R_j.Add(cLambda_jY_j)

			if !z_jG.Equal(rhs) {
				return nil, errors.Errorf("%s participant with shamir id %d is misbehaving", error_types.EAbort, j)
			}
		}
	}

	z := sa.CohortConfig.CipherSuite.Curve.Scalar.Zero()
	for _, partialSignature := range partialSignatures {
		z = z.Add(partialSignature.Zi)
	}

	sigma := &frost.Signature{R: sa.parameters.R, Z: z}

	if err := frost.Verify(sa.CohortConfig.CipherSuite.Curve, sa.CohortConfig.CipherSuite.Hash, sigma, sa.PublicKey, sa.Message); err != nil {
		return nil, errors.Wrapf(err, "%s could not verify frost signature", error_types.EVerificationFailed)
	}
	return sigma, nil
}
