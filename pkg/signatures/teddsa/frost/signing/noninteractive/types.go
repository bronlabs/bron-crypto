package noninteractive

import (
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
		return errors.New("attested commitment to nonce is nil")
	}
	if ac.Attestor == nil {
		return errors.New("attestor is nil")
	}
	if !cohortConfig.IsInCohort(ac.Attestor) {
		return errors.New("attestor is not in cohort")
	}
	if ac.D.IsIdentity() {
		return errors.New("D is at infinity")
	}
	if !ac.D.IsOnCurve() {
		return errors.New("D is not on the curve")
	}
	if ac.E.IsIdentity() {
		return errors.New("E is at infinity")
	}
	if !ac.E.IsOnCurve() {
		return errors.New("E is not on the curve")
	}
	if ac.D.CurveName() != ac.E.CurveName() {
		return errors.New("D and E are not on the same curve")
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
		return errors.New("presignature is nil")
	}
	attestorsHashSet := map[integration.IdentityKey]bool{}
	DHashSet := map[curves.Point]bool{}
	EHashSet := map[curves.Point]bool{}
	for _, thisPartyAttestedCommitment := range *ps {
		if attestorsHashSet[thisPartyAttestedCommitment.Attestor] {
			return errors.New("found duplicate attestor in this presignature")
		}
		if DHashSet[thisPartyAttestedCommitment.D] {
			return errors.New("found duplicate D")
		}
		if EHashSet[thisPartyAttestedCommitment.E] {
			return errors.New("found duplicate E")
		}
		if err := thisPartyAttestedCommitment.Validate(cohortConfig); err != nil {
			return errors.Wrap(err, "invalid attested commitments")
		}
		attestorsHashSet[thisPartyAttestedCommitment.Attestor] = true
		DHashSet[thisPartyAttestedCommitment.D] = true
		EHashSet[thisPartyAttestedCommitment.E] = true
	}
	for _, participant := range cohortConfig.Participants {
		if !attestorsHashSet[participant] {
			return errors.New("at least one party in the cohort does not have an attested commitment")
		}
	}
	if err := sortPreSignatureInPlace(cohortConfig, *ps); err != nil {
		return errors.Wrap(err, "couldn't sort presignature elements by shamir id")
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
		return errors.New("presignature is nil")
	}
	if err := cohortConfig.Validate(); err != nil {
		return errors.Wrap(err, "could not validate cohort config")
	}
	if len(*psb) <= 0 {
		return errors.New("batch is empty")
	}

	// checking for duplicates across all presignatures.
	DHashSet := map[curves.Point]bool{}
	EHashSet := map[curves.Point]bool{}
	for i, preSignature := range *psb {
		if err := preSignature.Validate(cohortConfig); err != nil {
			return errors.Wrapf(err, "presignature with index %d is invalid", i)
		}
		for _, D := range preSignature.Ds() {
			if DHashSet[D] {
				return errors.New("found duplicate D")
			}
			DHashSet[D] = true
		}
		for _, E := range preSignature.Es() {
			if EHashSet[E] {
				return errors.New("found duplicate E")
			}
			EHashSet[E] = true
		}
	}
	return nil
}

// We require that attested commitments within a presignature are sorted by the shamir id of the attestor.
func sortPreSignatureInPlace(cohortConfig *integration.CohortConfig, attestedCommitments []*AttestedCommitmentToNoncePair) error {
	shamirIdToIdentityKey, _, err := frost.DeriveShamirIds(nil, cohortConfig.Participants)
	if err != nil {
		return errors.Wrap(err, "couldn't derive shamir ids")
	}
	identityKeyToShamirId := map[integration.IdentityKey]int{}
	for shamirId, identityKey := range shamirIdToIdentityKey {
		identityKeyToShamirId[identityKey] = shamirId
	}

	sort.Slice(attestedCommitments, func(i, j int) bool {
		return identityKeyToShamirId[attestedCommitments[i].Attestor] < identityKeyToShamirId[attestedCommitments[j].Attestor]
	})
	return nil
}
