package boldyreva02

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/polynomials/interpolation/lagrange"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
)

var _ tsignatures.Shard = (*Shard[bls12381.G1])(nil)
var _ tsignatures.Shard = (*Shard[bls12381.G2])(nil)

type Shard[K bls.KeySubGroup] struct {
	SigningKeyShare *SigningKeyShare[K]
	PublicKeyShares *PartialPublicKeys[K]

	_ ds.Incomparable
}

func NewShard[K bls.KeySubGroup](protocol types.ThresholdProtocol, signingKeyShare *tsignatures.SigningKeyShare, partialPublicKeys *tsignatures.PartialPublicKeys) (*Shard[K], error) {
	if err := signingKeyShare.Validate(protocol); err != nil {
		return nil, errs.WrapValidation(err, "invalid signing key share")
	}
	if err := partialPublicKeys.Validate(protocol); err != nil {
		return nil, errs.WrapValidation(err, "invalid partial public keys")
	}

	publicKeyPoint, ok := signingKeyShare.PublicKey.(curves.PairingPoint)
	if !ok {
		return nil, errs.NewArgument("invalid share")
	}

	shard := &Shard[K]{
		SigningKeyShare: &SigningKeyShare[K]{
			Share: signingKeyShare.Share,
			PublicKey: &bls.PublicKey[K]{
				Y: publicKeyPoint,
			},
		},
		PublicKeyShares: &PartialPublicKeys[K]{
			PublicKey: &bls.PublicKey[K]{
				Y: publicKeyPoint,
			},
			Shares:                  partialPublicKeys.Shares,
			FeldmanCommitmentVector: partialPublicKeys.FeldmanCommitmentVector,
		},
	}

	return shard, nil
}

func (s *Shard[K]) Validate(protocol types.ThresholdProtocol) error {
	if err := s.SigningKeyShare.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "invalid signing key share")
	}
	if err := s.PublicKeyShares.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "invalid public key shares map")
	}
	return nil
}

func (s *Shard[_]) SecretShare() curves.Scalar {
	return s.SigningKeyShare.Share
}

func (s *Shard[_]) PublicKey() curves.Point {
	return s.SigningKeyShare.PublicKey.Y
}

func (s *Shard[_]) PartialPublicKeys() ds.Map[types.IdentityKey, curves.Point] {
	return s.PublicKeyShares.Shares
}

func (s *Shard[_]) FeldmanCommitmentVector() []curves.Point {
	return s.PublicKeyShares.FeldmanCommitmentVector
}

type SigningKeyShare[K bls.KeySubGroup] struct {
	Share     curves.Scalar
	PublicKey *bls.PublicKey[K]

	_ ds.Incomparable
}

func (s *SigningKeyShare[K]) Validate(protocol types.ThresholdProtocol) error {
	if s == nil {
		return errs.NewIsNil("signing key share is nil")
	}
	if s.Share.IsZero() {
		return errs.NewIsZero("share can't be zero")
	}
	if s.PublicKey.Y.IsIdentity() {
		return errs.NewIsIdentity("public key can't be at infinity")
	}
	if !curveutils.AllOfSameCurve(protocol.Curve(), s.Share, s.PublicKey.Y) {
		return errs.NewCurve("curve mismatch")
	}
	return nil
}

type PartialPublicKeys[K bls.KeySubGroup] struct {
	PublicKey               *bls.PublicKey[K]
	Shares                  ds.Map[types.IdentityKey, curves.Point]
	FeldmanCommitmentVector []curves.Point

	_ ds.Incomparable
}

func (p *PartialPublicKeys[K]) Validate(protocol types.ThresholdProtocol) error {
	if p == nil {
		return errs.NewIsNil("receiver of this method is nil")
	}
	if p.PublicKey == nil {
		return errs.NewIsNil("public key")
	}
	if len(p.FeldmanCommitmentVector) != int(protocol.Threshold()) {
		return errs.NewLength("feldman commitment vector length is invalid")
	}
	if p.Shares == nil {
		return errs.NewIsNil("shares map")
	}
	partialPublicKeyHolders := hashset.NewHashableHashSet(p.Shares.Keys()...)
	if !partialPublicKeyHolders.Equal(protocol.Participants()) {
		return errs.NewMembership("shares map is not equal to the participant set")
	}
	if !curveutils.AllPointsOfSameCurve(protocol.Curve(), p.PublicKey.Y) {
		return errs.NewCurve("public key")
	}
	if !curveutils.AllPointsOfSameCurve(protocol.Curve(), p.Shares.Values()...) {
		return errs.NewCurve("shares map")
	}
	if !curveutils.AllPointsOfSameCurve(protocol.Curve(), p.FeldmanCommitmentVector...) {
		return errs.NewCurve("feldman commitment vector")
	}

	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	sharingIds := make([]curves.Scalar, protocol.TotalParties())
	partialPublicKeys := make([]curves.Point, protocol.TotalParties())
	for i := 0; i < int(protocol.TotalParties()); i++ {
		sharingId := types.SharingID(i + 1)
		sharingIds[i] = p.PublicKey.Y.Curve().ScalarField().New(uint64(sharingId))
		identityKey, exists := sharingConfig.Get(sharingId)
		if !exists {
			return errs.NewMissing("missing identity key for sharing id %d", i+1)
		}
		partialPublicKey, exists := p.Shares.Get(identityKey)
		if !exists {
			return errs.NewMissing("partial public key doesn't exist for sharing id %d", sharingId)
		}
		partialPublicKeys[i] = partialPublicKey
	}
	evaluateAt := p.PublicKey.Y.Curve().ScalarField().Zero() // because f(0) would be the private key which means interpolating in the exponent should give us the public key
	reconstructedPublicKey, err := lagrange.InterpolateInTheExponent(p.PublicKey.Y.Curve(), sharingIds, partialPublicKeys, evaluateAt)
	if err != nil {
		return errs.WrapFailed(err, "could not interpolate partial public keys in the exponent")
	}
	if !reconstructedPublicKey.Equal(p.PublicKey.Y) {
		return errs.NewVerification("reconstructed public key is incorrect")
	}
	return nil
}

type PartialSignature[S bls.SignatureSubGroup] struct {
	SigmaI    *bls.Signature[S]
	SigmaPOPI *bls.Signature[S]
	POP       *bls.ProofOfPossession[S]

	_ ds.Incomparable
}
