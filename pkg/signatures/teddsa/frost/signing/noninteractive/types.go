package noninteractive

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/pkg/errors"
)

type AttestedCommitmentToNonce struct {
	Commitment  curves.Point
	Attestor    integration.IdentityKey
	Attestation []byte
}

func (ac *AttestedCommitmentToNonce) Validate(cohortConfig *integration.CohortConfig) error {
	if !cohortConfig.IsInCohort(ac.Attestor) {
		return errors.New("attestor is not in cohort")
	}
	if ac.Commitment.IsIdentity() {
		return errors.New("commitment is at infinity")
	}
	if !ac.Commitment.IsOnCurve() {
		return errors.New("commitment is not on the curve")
	}
	if err := ac.Attestor.Verify(ac.Attestation, ac.Attestor.PublicKey(), ac.Commitment.ToAffineCompressed()); err != nil {
		return errors.Wrap(err, "could not verify attestation")
	}
	return nil
}

type PreSignature struct {
	DRowsAttested []*AttestedCommitmentToNonce
	ERowsAttested []*AttestedCommitmentToNonce
}

type PrivateNoncePair struct {
	D curves.Scalar
	E curves.Scalar
}

func (ps *PreSignature) Validate(cohortConfig *integration.CohortConfig) error {
	if ps == nil {
		return errors.New("presignature is nil")
	}
	if len(ps.DRowsAttested) != len(ps.ERowsAttested) {
		return errors.New("presignature size malformed")
	}
	if err := cohortConfig.Validate(); err != nil {
		return errors.Wrap(err, "cohort config is invalid")
	}

	attestorsHashSet := map[integration.IdentityKey]bool{}
	for i := range ps.DRowsAttested {
		DRowAttested := ps.DRowsAttested[i]
		ERowAttested := ps.ERowsAttested[i]

		if !DRowAttested.Attestor.PublicKey().Equal(ERowAttested.Attestor.PublicKey()) {
			return errors.Errorf("attestor keys for D and E at index %d is not equal", i)
		}
		if err := DRowAttested.Validate(cohortConfig); err != nil {
			return errors.Wrap(err, "invalid attestation")
		}
		if err := ERowAttested.Validate(cohortConfig); err != nil {
			return errors.Wrap(err, "invalid attestation")
		}
		if attestorsHashSet[DRowAttested.Attestor] {
			return errors.New("found duplicate attestor")
		}
	}
	return nil
}
