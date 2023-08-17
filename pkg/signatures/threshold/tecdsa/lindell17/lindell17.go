package lindell17

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/paillier"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold"
)

const (
	// Threshold Lindell 2017 threshold (always 2).
	Threshold = 2
)

type Participant interface {
	integration.Participant

	IsSignatureAggregator() bool
}

type Shard struct {
	SigningKeyShare         *threshold.SigningKeyShare
	PaillierSecretKey       *paillier.SecretKey
	PaillierPublicKeys      map[helper_types.IdentityHash]*paillier.PublicKey
	PaillierEncryptedShares map[helper_types.IdentityHash]paillier.CipherText

	_ helper_types.Incomparable
}

type PartialSignature struct {
	C3 paillier.CipherText

	_ helper_types.Incomparable
}

type PreSignature struct {
	K    curves.Scalar
	BigR map[helper_types.IdentityHash]curves.Point

	_ helper_types.Incomparable
}

type PreSignatureBatch struct {
	PreSignatures []*PreSignature

	_ helper_types.Incomparable
}

func (s *Shard) Validate(cohortConfig *integration.CohortConfig) error {
	if err := s.SigningKeyShare.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "invalid signing key share")
	}
	// TODO: validate the rest of the paillier stuff
	// TODO: validate cohort membership after hashset is incorporated
	return nil
}
