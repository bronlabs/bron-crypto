package aggregation

import (
	"sort"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	schnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost"
)

var fiatShamir = hashing.NewSchnorrCompatibleFiatShamir()

type SignatureAggregator struct {
	CohortConfig           *integration.CohortConfig
	PublicKey              curves.Point
	MyIdentityKey          integration.IdentityKey
	SessionParticipants    *hashset.HashSet[integration.IdentityKey]
	IdentityKeyToSharingId map[types.IdentityHash]int
	PublicKeyShares        *frost.PublicKeyShares
	Message                []byte

	parameters *SignatureAggregatorParameters

	_ types.Incomparable
}

func (sa *SignatureAggregator) HasIdentifiableAbort() bool {
	return sa.PublicKeyShares != nil
}

type SignatureAggregatorParameters struct {
	Z_i     curves.Scalar
	R       curves.Point
	R_js    map[types.IdentityHash]curves.Point
	D_alpha map[types.IdentityHash]curves.Point
	E_alpha map[types.IdentityHash]curves.Point

	_ types.Incomparable
}

func (s *SignatureAggregatorParameters) Validate() error {
	if s == nil {
		return errs.NewIsNil("aggregation parameter is nil")
	}
	return nil
}

func NewSignatureAggregator(identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, shard *frost.Shard, sessionParticipants *hashset.HashSet[integration.IdentityKey], identityKeyToSharingId map[types.IdentityHash]int, message []byte, parameters *SignatureAggregatorParameters) (*SignatureAggregator, error) {
	if err := shard.Validate(cohortConfig); err != nil {
		return nil, errs.WrapFailed(err, "invalid shard")
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
	if err := aggregator.Validate(); err != nil {
		return nil, errs.WrapFailed(err, "invalid aggregator")
	}
	return aggregator, nil
}
func (sa *SignatureAggregator) Validate() error {
	if sa == nil {
		return errs.NewIsNil("aggregator is nil")
	}
	if err := sa.CohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "cohort config is invalid")
	}
	if !sa.CohortConfig.IsSignatureAggregator(sa.MyIdentityKey) {
		return errs.NewInvalidArgument("provided identity key is not a signature aggregator of the given cohort config")
	}
	if sa.CohortConfig.Protocol == nil {
		return errs.NewIsNil("protocol is nil")
	}
	if sa.SessionParticipants == nil {
		return errs.NewIsNil("must provide the list of the sharing ids of session participants")
	}
	if sa.SessionParticipants.Len() == 0 {
		return errs.NewIncorrectCount("must provide the list of the sharing ids of session participants")
	}
	if len(sa.IdentityKeyToSharingId) != sa.CohortConfig.Protocol.TotalParties {
		return errs.NewIncorrectCount("don't have enough mapping for shamir to identity keys as we have parties")
	}
	if sa.Message == nil {
		return errs.NewIsNil("message is empty")
	}
	if len(sa.Message) == 0 {
		return errs.NewIsZero("message is empty")
	}
	if err := sa.parameters.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "aggregation parameters are invalid")
	}
	if sa.HasIdentifiableAbort() {
		if len(sa.parameters.R_js) != sa.SessionParticipants.Len() {
			return errs.NewIncorrectCount("identifiable abort is enabled and the size of Rjs and S is not equal.")
		}
	}
	return nil
}

// TODO: condense/simplify.
func (sa *SignatureAggregator) Aggregate(partialSignatures map[types.IdentityHash]*frost.PartialSignature) (*schnorr.Signature, error) {
	if len(sa.parameters.D_alpha) != sa.SessionParticipants.Len() {
		return nil, errs.NewIncorrectCount("length of D_alpha is not equal to S")
	}
	if len(sa.parameters.E_alpha) != sa.SessionParticipants.Len() {
		return nil, errs.NewIncorrectCount("length of E_alpha is not equal to S")
	}
	// This is for TS-SUF-4 in case aggregator was the one computing the R
	// for identifiable abort, you need R_js
	recomputedR_js := map[types.IdentityHash]curves.Point{}
	if sa.parameters.R == nil {
		sa.parameters.R = sa.CohortConfig.CipherSuite.Curve.Point().Identity()
		combinedDsAndEs := []byte{}
		// we need to consistently order the Ds and Es
		sortedIdentities := integration.ByPublicKey(sa.SessionParticipants.List())
		sort.Sort(sortedIdentities)
		for _, presentParty := range sortedIdentities {
			combinedDsAndEs = append(combinedDsAndEs, sa.parameters.D_alpha[presentParty.Hash()].ToAffineCompressed()...)
			combinedDsAndEs = append(combinedDsAndEs, sa.parameters.E_alpha[presentParty.Hash()].ToAffineCompressed()...)
		}

		for _, jIdentityKey := range sa.SessionParticipants.Iter() {
			j := sa.IdentityKeyToSharingId[jIdentityKey.Hash()]

			r_j, err := sa.CohortConfig.CipherSuite.Curve.Scalar().Hash([]byte{byte(j)}, sa.Message, combinedDsAndEs)
			if err != nil {
				return nil, errs.WrapHashingFailed(err, "could not hash for r_j")
			}
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
		shamirConfig, err := shamir.NewDealer(sa.CohortConfig.Protocol.Threshold, sa.CohortConfig.Protocol.TotalParties, sa.CohortConfig.CipherSuite.Curve)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not initialise shamir config")
		}

		var sharingIDs []int
		for _, party := range sa.SessionParticipants.Iter() {
			var ok bool
			sharingID, ok := sa.IdentityKeyToSharingId[party.Hash()]
			if !ok {
				return nil, errs.NewMissing("could not find sharing id for the party")
			}
			sharingIDs = append(sharingIDs, sharingID)
		}
		lagrangeCoefficients, err := shamirConfig.LagrangeCoefficients(sharingIDs)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not compute lagrange coefficients")
		}

		c, err := fiatShamir.GenerateChallenge(
			sa.CohortConfig.CipherSuite,
			sa.parameters.R.ToAffineCompressed(),
			sa.PublicKey.ToAffineCompressed(),
			sa.Message,
		)
		if err != nil {
			return nil, errs.WrapSerializationError(err, "converting hash to c failed")
		}

		for _, jIdentityKey := range sa.SessionParticipants.Iter() {
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
				return nil, errs.NewIdentifiableAbort(j, "participant with sharing id is misbehaving")
			}
		}
	}

	s := sa.CohortConfig.CipherSuite.Curve.Scalar().Zero()
	for _, partialSignature := range partialSignatures {
		s = s.Add(partialSignature.Zi)
	}

	sigma := &schnorr.Signature{R: sa.parameters.R, S: s}

	if err := schnorr.Verify(sa.CohortConfig.CipherSuite, &schnorr.PublicKey{A: sa.PublicKey}, sa.Message, sigma); err != nil {
		return nil, errs.WrapVerificationFailed(err, "could not verify frost signature")
	}
	return sigma, nil
}
