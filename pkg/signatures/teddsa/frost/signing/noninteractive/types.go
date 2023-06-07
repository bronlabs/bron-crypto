package noninteractive

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"sort"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost"
	"github.com/pkg/errors"
)

type PrivateNoncePair struct {
	SmallD curves.Scalar
	SmallE curves.Scalar
}

type AttestedCommitmentToNoncePair struct {
	Attestor    integration.IdentityKey
	D           curves.Point
	E           curves.Point
	Attestation []byte
}

func (ac *AttestedCommitmentToNoncePair) Validate(cohortConfig *integration.CohortConfig) error {
	if ac == nil {
		return errors.Errorf("%s attested commitment to nonce is nil", errs.IsNil)
	}
	if ac.Attestor == nil {
		return errors.Errorf("%s attestor is nil", errs.IsNil)
	}
	if !cohortConfig.IsInCohort(ac.Attestor) {
		return errors.Errorf("%s attestor is not in cohort", errs.InvalidArgument)
	}
	if ac.D.IsIdentity() {
		return errors.Errorf("%s D is at infinity", errs.IsIdentity)
	}
	if !ac.D.IsOnCurve() {
		return errors.Errorf("%s D is not on the curve", errs.NotOnCurve)
	}
	if ac.E.IsIdentity() {
		return errors.Errorf("%s E is at infinity", errs.IsIdentity)
	}
	if !ac.E.IsOnCurve() {
		return errors.Errorf("%s E is not on the curve", errs.NotOnCurve)
	}
	if ac.D.CurveName() != ac.E.CurveName() {
		return errors.Errorf("%s D and E are not on the same curve %s != %s", errs.InvalidCurve, ac.D.CurveName(), ac.E.CurveName())
	}
	message := ac.D.ToAffineCompressed()
	message = append(message, ac.E.ToAffineCompressed()...)
	if err := ac.Attestor.Verify(ac.Attestation, ac.Attestor.PublicKey(), message); err != nil {
		return errors.Wrap(err, "could not verify attestation")
	}
	return nil
}

type PreSignature []*AttestedCommitmentToNoncePair

func (ps *PreSignature) Validate(cohortConfig *integration.CohortConfig) error {
	if ps == nil {
		return errors.Errorf("%s presignature is nil", errs.IsNil)
	}
	attestorsHashSet := map[integration.IdentityKey]bool{}
	DHashSet := map[curves.Point]bool{}
	EHashSet := map[curves.Point]bool{}
	for _, thisPartyAttestedCommitment := range *ps {
		if attestorsHashSet[thisPartyAttestedCommitment.Attestor] {
			return errors.Errorf("%s found duplicate attestor in this presignature", errs.Duplicate)
		}
		if DHashSet[thisPartyAttestedCommitment.D] {
			return errors.Errorf("%s found duplicate D", errs.Duplicate)
		}
		if EHashSet[thisPartyAttestedCommitment.E] {
			return errors.Errorf("%s found duplicate E", errs.Duplicate)
		}
		if err := thisPartyAttestedCommitment.Validate(cohortConfig); err != nil {
			return errors.Wrapf(err, "%s invalid attested commitments", errs.VerificationFailed)
		}
		attestorsHashSet[thisPartyAttestedCommitment.Attestor] = true
		DHashSet[thisPartyAttestedCommitment.D] = true
		EHashSet[thisPartyAttestedCommitment.E] = true
	}
	for _, participant := range cohortConfig.Participants {
		if !attestorsHashSet[participant] {
			return errors.Errorf("%s at least one party in the cohort does not have an attested commitment", errs.Missing)
		}
	}
	if err := sortPreSignatureInPlace(cohortConfig, *ps); err != nil {
		return errors.Wrapf(err, "%s couldn't sort presignature elements by shamir id", errs.Failed)
	}
	return nil
}

func (ps *PreSignature) Ds() []curves.Point {
	result := make([]curves.Point, len(*ps))
	for i := 0; i < len(*ps); i++ {
		result[i] = (*ps)[i].D
	}
	return result
}

func (ps *PreSignature) Es() []curves.Point {
	result := make([]curves.Point, len(*ps))
	for i := 0; i < len(*ps); i++ {
		result[i] = (*ps)[i].E
	}
	return result
}

type PreSignatureBatch []*PreSignature

// TODO: serialization/deserialization
type preSignatureBatchJSON struct {
	Attestors     []integration.IdentityKey
	PreSignatures []*PreSignature
}

func (psb *PreSignatureBatch) Validate(cohortConfig *integration.CohortConfig) error {
	if psb == nil {
		return errors.Errorf("%s presignature is nil", errs.IsNil)
	}
	if err := cohortConfig.Validate(); err != nil {
		return errors.Wrapf(err, "%s could not validate cohort config", errs.VerificationFailed)
	}
	if len(*psb) <= 0 {
		return errors.Errorf("%s batch is empty", errs.IsZero)
	}

	// checking for duplicates across all presignatures.
	DHashSet := map[curves.Point]bool{}
	EHashSet := map[curves.Point]bool{}
	for i, preSignature := range *psb {
		if err := preSignature.Validate(cohortConfig); err != nil {
			return errors.Wrapf(err, "%s presignature with index %d is invalid", errs.VerificationFailed, i)
		}
		for _, D := range preSignature.Ds() {
			if DHashSet[D] {
				return errors.Errorf("%s found duplicate D", errs.Duplicate)
			}
			DHashSet[D] = true
		}
		for _, E := range preSignature.Es() {
			if EHashSet[E] {
				return errors.Errorf("%s found duplicate E", errs.Duplicate)
			}
			EHashSet[E] = true
		}
	}
	return nil
}

// We require that attested commitments within a presignature are sorted by the shamir id of the attestor.
func sortPreSignatureInPlace(cohortConfig *integration.CohortConfig, attestedCommitments []*AttestedCommitmentToNoncePair) error {
	_, identityKeyToShamirId, _ := frost.DeriveShamirIds(nil, cohortConfig.Participants)
	sort.Slice(attestedCommitments, func(i, j int) bool {
		return identityKeyToShamirId[attestedCommitments[i].Attestor] < identityKeyToShamirId[attestedCommitments[j].Attestor]
	})
	return nil
}
