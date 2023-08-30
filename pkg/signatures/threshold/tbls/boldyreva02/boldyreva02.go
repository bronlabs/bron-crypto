package boldyreva02

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/core/polynomials"
	"github.com/copperexchange/knox-primitives/pkg/signatures/bls"
)

type Participant interface {
	integration.Participant

	IsSignatureAggregator() bool
}

type SigningKeyShare[K bls.KeySubGroup] struct {
	Share     curves.PairingScalar
	PublicKey *bls.PublicKey[K]

	_ helper_types.Incomparable
}

func (s *SigningKeyShare[K]) Validate() error {
	if s == nil {
		return errs.NewIsNil("signing key share is nil")
	}
	if s.Share.IsZero() {
		return errs.NewIsZero("share can't be zero")
	}
	if err := s.PublicKey.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "public key is invalid")
	}
	return nil
}

type PublicKeyShares[K bls.KeySubGroup] struct {
	PublicKey *bls.PublicKey[K]
	SharesMap map[helper_types.IdentityHash]curves.PairingPoint

	_ helper_types.Incomparable
}

func (p *PublicKeyShares[K]) Validate(cohortConfig *integration.CohortConfig) error {
	if p == nil {
		return errs.NewIsNil("receiver is nil")
	}
	if p.PublicKey == nil {
		return errs.NewIsNil("public key is nil")
	}
	curve := p.PublicKey.Y.Curve()
	pointInK := new(K)

	if p.PublicKey.Y.CurveName() != (*pointInK).CurveName() {
		return errs.NewInvalidCurve("key subgroup is different than public key subgroup")
	}

	sharingIdToIdentityKey, _, _ := integration.DeriveSharingIds(nil, cohortConfig.Participants)
	sharingIds := make([]curves.Scalar, cohortConfig.Participants.Len())
	partialPublicKeys := make([]curves.Point, cohortConfig.Participants.Len())
	for i := 0; i < cohortConfig.Participants.Len(); i++ {
		sharingIds[i] = curve.Scalar().New(uint64(i + 1))
		identityKey, exists := sharingIdToIdentityKey[i+1]
		if !exists {
			return errs.NewMissing("missing identity key for sharing id %d", i+1)
		}
		partialPublicKey, exists := p.SharesMap[identityKey.Hash()]
		if !exists {
			return errs.NewMissing("partial public key doesn't exist for id hash %x", identityKey.Hash())
		}
		if partialPublicKey.CurveName() != (*pointInK).CurveName() {
			return errs.NewInvalidCurve("partial public key %d is in wrong subgroup", i)
		}
		partialPublicKeys[i] = partialPublicKey
	}
	evaluateAt := curve.Scalar().New(0) // because f(0) would be the private key which means interpolating in the exponent should give us the public key
	reconstructedPublicKey, err := polynomials.InterpolateInTheExponent(curve, sharingIds, partialPublicKeys, evaluateAt)
	if err != nil {
		return errs.WrapFailed(err, "could not interpolate partial public keys in the exponent")
	}
	if !reconstructedPublicKey.Equal(p.PublicKey.Y) {
		return errs.NewVerificationFailed("reconstructed public key is incorrect")
	}
	return nil
}

type Shard[K bls.KeySubGroup] struct {
	SigningKeyShare *SigningKeyShare[K]
	PublicKeyShares *PublicKeyShares[K]

	_ helper_types.Incomparable
}

func (s *Shard[K]) Validate(cohortConfig *integration.CohortConfig) error {
	if err := s.SigningKeyShare.Validate(); err != nil {
		return errs.WrapVerificationFailed(err, "invalid signing key share")
	}
	if err := s.PublicKeyShares.Validate(cohortConfig); err != nil {
		return errs.WrapVerificationFailed(err, "invalid public key shares map")
	}
	return nil
}

type PartialSignature[S bls.SignatureSubGroup] struct {
	Sigma_i *bls.Signature[S]
	POP     *bls.ProofOfPossession[S]

	_ helper_types.Incomparable
}
