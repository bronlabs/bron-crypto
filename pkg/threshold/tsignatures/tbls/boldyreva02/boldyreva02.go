package boldyreva02

import (
	"encoding/json"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/curveutils"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/polynomials/interpolation/lagrange"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/bls"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures"
)

var _ tsignatures.Shard = (*Shard[bls12381.G1])(nil)
var _ tsignatures.Shard = (*Shard[bls12381.G2])(nil)

type Shard[K bls.KeySubGroup] struct {
	SigningKeyShare *SigningKeyShare[K]
	PublicKeyShares *PartialPublicKeys[K]

	_ ds.Incomparable
}

func (s *Shard[K]) Equal(other tsignatures.Shard) bool {
	otherShard, ok := other.(*Shard[K])
	return ok && s.SigningKeyShare.Equal(otherShard.SigningKeyShare) && s.PublicKeyShares.Equal(otherShard.PublicKeyShares)
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

func (s *Shard[_]) PartialPublicKeys() ds.Map[types.SharingID, curves.Point] {
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

func (s *SigningKeyShare[K]) Equal(other *SigningKeyShare[K]) bool {
	return other != nil && s.Share != nil && s.PublicKey != nil && s.Share.Equal(other.Share) && s.PublicKey.Equal(other.PublicKey)
}

func (s *SigningKeyShare[K]) Validate(protocol types.ThresholdProtocol) error {
	if s == nil {
		return errs.NewIsNil("signing key share is nil")
	}
	if s.Share.IsZero() {
		return errs.NewIsZero("share can't be zero")
	}
	if s.PublicKey.Y.IsAdditiveIdentity() {
		return errs.NewIsIdentity("public key can't be at infinity")
	}
	if !s.PublicKey.Y.IsInPrimeSubGroup() {
		return errs.NewValidation("Public Key not in the prime subgroup")
	}
	if !curveutils.AllOfSameCurve(protocol.Curve(), s.Share, s.PublicKey.Y) {
		return errs.NewCurve("curve mismatch")
	}
	return nil
}

func (s *SigningKeyShare[K]) MarshalJSON() ([]byte, error) {
	publicKeySerialised, err := s.PublicKey.MarshalBinary()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to marshal public key")
	}
	out, err := json.Marshal(&struct {
		Share     curves.Scalar
		PublicKey []byte
	}{
		Share:     s.Share,
		PublicKey: publicKeySerialised,
	})
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal signing key share")
	}
	return out, nil
}

func (s *SigningKeyShare[K]) UnmarshalJSON(data []byte) error {
	var decoded struct {
		Share     json.RawMessage
		PublicKey []byte
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return errs.WrapFailed(err, "failed to unmarshal signing key share")
	}
	share, err := curveutils.NewScalarFromJSON(decoded.Share)
	if err != nil {
		return errs.WrapFailed(err, "failed to unmarshal share")
	}
	publicKey := &bls.PublicKey[K]{}
	if err := publicKey.UnmarshalBinary(decoded.PublicKey); err != nil {
		return errs.WrapFailed(err, "failed to unmarshal public key")
	}
	s.Share = share
	s.PublicKey = publicKey
	return nil
}

type PartialPublicKeys[K bls.KeySubGroup] struct {
	PublicKey               *bls.PublicKey[K]
	Shares                  ds.Map[types.SharingID, curves.Point]
	FeldmanCommitmentVector []curves.Point

	_ ds.Incomparable
}

func (p *PartialPublicKeys[K]) Equal(other *PartialPublicKeys[K]) bool {
	if other == nil {
		return false
	}
	if p.PublicKey == nil || !p.PublicKey.Equal(other.PublicKey) {
		return false
	}

	if p.Shares == nil || other.Shares == nil {
		return false
	}
	for identity, partialShare := range p.Shares.Iter() {
		otherShare, exists := other.Shares.Get(identity)
		if !exists {
			return false
		}
		if !partialShare.Equal(otherShare) {
			return false
		}
	}

	if len(p.FeldmanCommitmentVector) != len(other.FeldmanCommitmentVector) {
		return false
	}
	for i, point := range p.FeldmanCommitmentVector {
		if !point.Equal(other.FeldmanCommitmentVector[i]) {
			return false
		}
	}
	return true
}

func (p *PartialPublicKeys[K]) IdentityBasedMapping(participants ds.Set[types.IdentityKey]) ds.Map[types.IdentityKey, curves.Point] {
	sharingConfig := types.DeriveSharingConfig(participants)
	result := hashmap.NewHashableHashMap[types.IdentityKey, curves.Point]()
	for sharingId, partialPublicKey := range p.Shares.Iter() {
		identityKey, exists := sharingConfig.Get(sharingId)
		if !exists {
			panic(errs.NewMissing("could not find identity key for sharing id %d", sharingId))
		}
		result.Put(identityKey, partialPublicKey)
	}
	return result
}

func (p *PartialPublicKeys[K]) Validate(protocol types.ThresholdProtocol) error {
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	if err := p.ValidateWithSharingConfig(sharingConfig); err != nil {
		return errs.WrapValidation(err, "invalid partial public keys")
	}
	if !curveutils.AllPointsOfSameCurve(protocol.Curve(), p.PublicKey.Y) {
		return errs.NewCurve("public key")
	}
	if len(p.FeldmanCommitmentVector) != int(protocol.Threshold()) {
		return errs.NewLength("feldman commitment vector length is invalid")
	}
	// partialPublicKeyHolders := hashset.NewHashableHashSet(p.Shares.Keys()...)
	// if !partialPublicKeyHolders.Equal(protocol.Participants()) {
	// 	return errs.NewMembership("shares map is not equal to the participant set")
	// }
	return nil
}

func (p *PartialPublicKeys[K]) ValidateWithSharingConfig(sharingConfig types.SharingConfig) error {
	if p == nil {
		return errs.NewIsNil("receiver of this method is nil")
	}
	if p.PublicKey == nil {
		return errs.NewIsNil("public key")
	}
	if !p.PublicKey.Y.IsInPrimeSubGroup() {
		return errs.NewValidation("Public Key not in the prime subgroup")
	}
	if p.Shares == nil {
		return errs.NewIsNil("shares map")
	}
	if !curveutils.AllPointsOfSameCurve(p.PublicKey.Y.Curve(), p.Shares.Values()...) {
		return errs.NewCurve("shares map")
	}
	if !curveutils.AllPointsOfSameCurve(p.PublicKey.Y.Curve(), p.FeldmanCommitmentVector...) {
		return errs.NewCurve("feldman commitment vector")
	}

	sharingIds := make([]curves.Scalar, sharingConfig.Size())
	partialPublicKeys := make([]curves.Point, sharingConfig.Size())
	for i := 0; i < sharingConfig.Size(); i++ {
		sharingId := types.SharingID(i + 1)
		sharingIds[i] = p.PublicKey.Y.Curve().ScalarField().New(uint64(sharingId))
		partialPublicKey, exists := p.Shares.Get(sharingId)
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

func (p *PartialPublicKeys[K]) MarshalJSON() ([]byte, error) {
	publicKeySerialised, err := p.PublicKey.MarshalBinary()
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to marshal public key")
	}
	sharesStructure, ok := p.Shares.(*hashmap.ComparableHashMap[types.SharingID, curves.Point])
	if !ok {
		return nil, errs.NewType("shares map is not of the correct type")
	}
	out, err := json.Marshal(&struct {
		PublicKey               []byte
		Shares                  *hashmap.ComparableHashMap[types.SharingID, curves.Point]
		FeldmanCommitmentVector []curves.Point
	}{
		PublicKey:               publicKeySerialised,
		Shares:                  sharesStructure,
		FeldmanCommitmentVector: p.FeldmanCommitmentVector,
	})
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal partial public keys")
	}
	return out, nil
}

func (p *PartialPublicKeys[K]) UnmarshalJSON(data []byte) error {
	var temp struct {
		PublicKey               []byte
		Shares                  *hashmap.ComparableHashMap[types.SharingID, json.RawMessage]
		FeldmanCommitmentVector []json.RawMessage
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return errs.WrapFailed(err, "failed to unmarshal partial public keys")
	}
	publicKey := &bls.PublicKey[K]{}
	if err := publicKey.UnmarshalBinary(temp.PublicKey); err != nil {
		return errs.WrapFailed(err, "failed to unmarshal public key")
	}
	unmarshaledShares := hashmap.NewComparableHashMap[types.SharingID, curves.Point]()
	for sharingId, rawPoint := range temp.Shares.Iter() {
		point, err := curveutils.NewPointFromJSON(rawPoint)
		if err != nil {
			return errs.WrapSerialisation(err, "could not unmarshal partial public key")
		}
		unmarshaledShares.Put(sharingId, point)
	}
	feldmanCommitmentVector := make([]curves.Point, len(temp.FeldmanCommitmentVector))
	for i, commitment := range temp.FeldmanCommitmentVector {
		point, err := curveutils.NewPointFromJSON(commitment)
		if err != nil {
			return errs.WrapSerialisation(err, "failed to unmarshal feldman commitment vector")
		}
		feldmanCommitmentVector[i] = point
	}
	p.PublicKey = publicKey
	p.Shares = unmarshaledShares
	p.FeldmanCommitmentVector = feldmanCommitmentVector
	return nil
}

type PartialSignature[S bls.SignatureSubGroup] struct {
	SigmaI    *bls.Signature[S]
	SigmaPOPI *bls.Signature[S]
	POP       *bls.ProofOfPossession[S]

	_ ds.Incomparable
}

func (p *PartialSignature[S]) Validate(protocol types.ThresholdProtocol) error {
	if p == nil {
		return errs.NewIsNil("partial signature is nil")
	}
	if p.SigmaI == nil {
		return errs.NewIsNil("sigma i")
	}
	if p.POP == nil {
		return errs.NewIsNil("pop")
	}
	if !curveutils.AllOfSameCurve(bls12381.GetSourceSubGroup[S](), p.SigmaI.Value, p.POP.Value) {
		return errs.NewCurve("curve mismatch")
	}
	if p.SigmaPOPI != nil {
		if !curveutils.AllOfSameCurve(bls12381.GetSourceSubGroup[S](), p.SigmaPOPI.Value) {
			return errs.NewCurve("curve mismatch")
		}
	}
	return nil
}
