package noninteractive_signing

import (
	"sort"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
)

type PrivateNoncePair struct {
	SmallD curves.Scalar
	SmallE curves.Scalar

	_ types.Incomparable
}

type AttestedCommitmentToNoncePair struct {
	Attestor    integration.IdentityKey
	D           curves.Point
	E           curves.Point
	Attestation []byte

	_ types.Incomparable
}

func (ac *AttestedCommitmentToNoncePair) Validate(cohortConfig *integration.CohortConfig) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapInvalidArgument(err, "cohort config is invalid")
	}
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
		return errs.NewMembershipError("D is not on the curve")
	}
	if ac.E.IsIdentity() {
		return errs.NewIsIdentity("E is at infinity")
	}
	if !ac.E.IsOnCurve() {
		return errs.NewMembershipError("E is not on the curve")
	}
	dCurve := ac.D.Curve()
	eCurve := ac.E.Curve()

	if dCurve.Name() != eCurve.Name() {
		return errs.NewInvalidCurve("D and E are not on the same curve %s != %s", dCurve.Name(), eCurve.Name())
	}
	message := ac.D.ToAffineCompressed()
	message = append(message, ac.E.ToAffineCompressed()...)
	if err := ac.Attestor.Verify(ac.Attestation, message); err != nil {
		return errs.WrapVerificationFailed(err, "could not verify attestation")
	}
	return nil
}

type PreSignature []*AttestedCommitmentToNoncePair

func (ps *PreSignature) Validate(cohortConfig *integration.CohortConfig) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapInvalidArgument(err, "cohort config is invalid")
	}
	if ps == nil {
		return errs.NewIsNil("presignature is nil")
	}
	i := -1
	for _, participant := range cohortConfig.Participants.Iter() {
		i++
		if participant == nil {
			return errs.NewIsNil("participant %d is nil", i)
		}
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
	err := sortPreSignatureInPlace(cohortConfig, *ps)
	if err != nil {
		return errs.WrapVerificationFailed(err, "could not sort presignature")
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

// TODO: serialisation/deserialisation.
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
func sortPreSignatureInPlace(cohortConfig *integration.CohortConfig, attestedCommitments []*AttestedCommitmentToNoncePair) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapInvalidArgument(err, "cohort config is invalid")
	}
	_, identityKeyToSharingId, _ := integration.DeriveSharingIds(nil, cohortConfig.Participants)
	sort.Slice(attestedCommitments, func(i, j int) bool {
		return identityKeyToSharingId[attestedCommitments[i].Attestor.Hash()] < identityKeyToSharingId[attestedCommitments[j].Attestor.Hash()]
	})
	return nil
}
