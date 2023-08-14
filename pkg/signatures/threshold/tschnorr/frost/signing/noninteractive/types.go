package noninteractive

import (
	"sort"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashset"
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
		return errs.NewIsNil("attested commitment to nonce is nil")
	}
	if ac.Attestor == nil {
		return errs.NewIsNil("attestor is nil")
	}
	if !cohortConfig.IsInCohort(ac.Attestor) {
		return errs.NewInvalidArgument("attestor is not in cohort")
	}
	if ac.D.IsIdentity() {
		return errs.NewIsIdentity("D is at infinity")
	}
	if !ac.D.IsOnCurve() {
		return errs.NewNotOnCurve("D is not on the curve")
	}
	if ac.E.IsIdentity() {
		return errs.NewIsIdentity("E is at infinity")
	}
	if !ac.E.IsOnCurve() {
		return errs.NewNotOnCurve("E is not on the curve")
	}
	dCurve, err := ac.D.Curve()
	if err != nil {
		return errs.WrapFailed(err, "could not extract D curve")
	}

	eCurve, err := ac.E.Curve()
	if err != nil {
		return errs.WrapFailed(err, "could not extract E curve")
	}

	if dCurve.Name() != eCurve.Name() {
		return errs.NewInvalidCurve("D and E are not on the same curve %s != %s", dCurve.Name(), eCurve.Name())
	}
	message := ac.D.ToAffineCompressed()
	message = append(message, ac.E.ToAffineCompressed()...)
	if err := ac.Attestor.Verify(ac.Attestation, ac.Attestor.PublicKey(), message); err != nil {
		return errs.WrapVerificationFailed(err, "could not verify attestation")
	}
	return nil
}

type PreSignature []*AttestedCommitmentToNoncePair

func (ps *PreSignature) Validate(cohortConfig *integration.CohortConfig) error {
	if ps == nil {
		return errs.NewIsNil("presignature is nil")
	}
	for i, participant := range cohortConfig.Participants {
		if participant == nil {
			return errs.NewIsNil("participant %d is nil", i)
		}
	}
	attestorsHashSet, err := hashset.NewHashSet(cohortConfig.Participants)
	if err != nil {
		return errs.WrapFailed(err, "could not construct participant hash set")
	}
	DHashSet := map[curves.Point]bool{}
	EHashSet := map[curves.Point]bool{}
	for _, thisPartyAttestedCommitment := range *ps {
		if DHashSet[thisPartyAttestedCommitment.D] {
			return errs.NewDuplicate("found duplicate D")
		}
		if EHashSet[thisPartyAttestedCommitment.E] {
			return errs.NewDuplicate("found duplicate E")
		}
		if err := thisPartyAttestedCommitment.Validate(cohortConfig); err != nil {
			return errs.WrapVerificationFailed(err, "invalid attested commitments")
		}
		DHashSet[thisPartyAttestedCommitment.D] = true
		EHashSet[thisPartyAttestedCommitment.E] = true
	}
	for _, participant := range cohortConfig.Participants {
		_, found := attestorsHashSet.Get(participant)
		if !found {
			return errs.NewMissing("at least one party in the cohort does not have an attested commitment")
		}
	}
	sortPreSignatureInPlace(cohortConfig, *ps)
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

// TODO: serialisation/deserialization.
type PreSignatureBatch []*PreSignature

func (psb *PreSignatureBatch) Validate(cohortConfig *integration.CohortConfig) error {
	if psb == nil {
		return errs.NewIsNil("presignature is nil")
	}
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "could not validate cohort config")
	}
	if len(*psb) == 0 {
		return errs.NewIsZero("batch is empty")
	}

	// checking for duplicates across all presignatures.
	DHashSet := map[curves.Point]bool{}
	EHashSet := map[curves.Point]bool{}
	for i, preSignature := range *psb {
		if err := preSignature.Validate(cohortConfig); err != nil {
			return errs.WrapVerificationFailed(err, "presignature with index %d is invalid", i)
		}
		for _, D := range preSignature.Ds() {
			if DHashSet[D] {
				return errs.NewDuplicate("found duplicate D")
			}
			DHashSet[D] = true
		}
		for _, E := range preSignature.Es() {
			if EHashSet[E] {
				return errs.NewDuplicate("found duplicate E")
			}
			EHashSet[E] = true
		}
	}
	return nil
}

// We require that attested commitments within a presignature are sorted by the sharing id of the attestor.
func sortPreSignatureInPlace(cohortConfig *integration.CohortConfig, attestedCommitments []*AttestedCommitmentToNoncePair) {
	_, identityKeyToSharingId, _ := integration.DeriveSharingIds(nil, cohortConfig.Participants)
	sort.Slice(attestedCommitments, func(i, j int) bool {
		return identityKeyToSharingId[attestedCommitments[i].Attestor.Hash()] < identityKeyToSharingId[attestedCommitments[j].Attestor.Hash()]
	})
}
