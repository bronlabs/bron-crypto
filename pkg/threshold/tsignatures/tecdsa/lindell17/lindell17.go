package lindell17

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
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
	SigningKeyShare         *tsignatures.SigningKeyShare
	PaillierSecretKey       *paillier.SecretKey
	PaillierPublicKeys      map[types.IdentityHash]*paillier.PublicKey
	PaillierEncryptedShares map[types.IdentityHash]*paillier.CipherText

	_ types.Incomparable
}

type PartialSignature struct {
	C3 *paillier.CipherText

	_ types.Incomparable
}

type PreSignature struct {
	K    curves.Scalar
	BigR map[types.IdentityHash]curves.Point

	_ types.Incomparable
}

type PreSignatureBatch struct {
	PreSignatures []*PreSignature

	_ types.Incomparable
}

func (s *Shard) Validate(cohortConfig *integration.CohortConfig) error {
	if err := s.SigningKeyShare.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "invalid signing key share")
	}
	// TODO: validate the rest of the paillier stuff
	// TODO: validate cohort membership after hashset is incorporated
	return nil
}
