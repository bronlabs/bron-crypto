package noninteractive

import (
	"sort"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
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
	if ac.D.CurveName() != ac.E.CurveName() {
		return errs.NewInvalidCurve("D and E are not on the same curve %s != %s", ac.D.CurveName(), ac.E.CurveName())
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
		return errs.NewIsNil("presignature is nil")
	}
	attestorsHashSet := map[integration.IdentityKey]bool{}
	DHashSet := map[curves.Point]bool{}
	EHashSet := map[curves.Point]bool{}
	for _, thisPartyAttestedCommitment := range *ps {
		if attestorsHashSet[thisPartyAttestedCommitment.Attestor] {
			return errs.NewDuplicate("found duplicate attestor in this presignature")
		}
		if DHashSet[thisPartyAttestedCommitment.D] {
			return errs.NewDuplicate("found duplicate D")
		}
		if EHashSet[thisPartyAttestedCommitment.E] {
			return errs.NewDuplicate("found duplicate E")
		}
		if err := thisPartyAttestedCommitment.Validate(cohortConfig); err != nil {
			return errs.WrapVerificationFailed(err, "invalid attested commitments")
		}
		attestorsHashSet[thisPartyAttestedCommitment.Attestor] = true
		DHashSet[thisPartyAttestedCommitment.D] = true
		EHashSet[thisPartyAttestedCommitment.E] = true
	}
	for _, participant := range cohortConfig.Participants {
		if !attestorsHashSet[participant] {
			return errs.NewMissing("at least one party in the cohort does not have an attested commitment")
		}
	}
	if err := sortPreSignatureInPlace(cohortConfig, *ps); err != nil {
		return errs.WrapFailed(err, "couldn't sort presignature elements by shamir id")
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
		return errs.NewIsNil("presignature is nil")
	}
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "could not validate cohort config")
	}
	if len(*psb) <= 0 {
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

// We require that attested commitments within a presignature are sorted by the shamir id of the attestor.
func sortPreSignatureInPlace(cohortConfig *integration.CohortConfig, attestedCommitments []*AttestedCommitmentToNoncePair) error {
	_, identityKeyToShamirId, _ := integration.DeriveSharingIds(nil, cohortConfig.Participants)
	sort.Slice(attestedCommitments, func(i, j int) bool {
		return identityKeyToShamirId[attestedCommitments[i].Attestor] < identityKeyToShamirId[attestedCommitments[j].Attestor]
	})
	return nil
}
