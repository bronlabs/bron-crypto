package tsignatures

import (
	"encoding/json"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curveutils"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials/interpolation/lagrange"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
)

type Shard interface {
	SecretShare() curves.Scalar
	PublicKey() curves.Point
	PartialPublicKeys() ds.Map[types.SharingID, curves.Point]
	FeldmanCommitmentVector() []curves.Point

	ds.Equatable[Shard]
}

type SigningKeyShare struct {
	Share     curves.Scalar
	PublicKey curves.Point

	_ ds.Incomparable
}

func (s *SigningKeyShare) Validate(protocol types.ThresholdProtocol) error {
	if s == nil {
		return errs.NewIsNil("signing key share is nil")
	}
	if s.Share.IsZero() {
		return errs.NewIsZero("share can't be zero")
	}
	if s.PublicKey.IsAdditiveIdentity() {
		return errs.NewIsIdentity("public key can't be at infinity")
	}
	if !s.PublicKey.IsInPrimeSubGroup() {
		return errs.NewValidation("Public Key not in the prime subgroup")
	}
	if !curveutils.AllOfSameCurve(protocol.Curve(), s.Share, s.PublicKey) {
		return errs.NewCurve("curve mismatch")
	}
	return nil
}

func (s *SigningKeyShare) ToAdditive(myIdentityKey types.IdentityKey, quorum ds.Set[types.IdentityKey], protocol types.ThresholdProtocol) (curves.Scalar, error) {
	if !quorum.IsSubSet(protocol.Participants()) {
		return nil, errs.NewMembership("present participants is not a subset of total participants")
	}
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId := uint(0)
	shamirIdentities := make([]uint, quorum.Size())
	i := 0
	for identityKey := range quorum.Iter() {
		sharingId, exists := sharingConfig.Reverse().Get(identityKey)
		if !exists {
			return nil, errs.NewMissing("could not find participant sharing id %s", identityKey.String())
		}
		if identityKey.Equal(myIdentityKey) {
			mySharingId = uint(sharingId)
		}
		shamirIdentities[i] = uint(sharingId)
		i++
	}
	if mySharingId == 0 {
		return nil, errs.NewMissing("could not find my sharing id")
	}
	shamirShare := &shamir.Share{
		Id:    mySharingId,
		Value: s.Share,
	}
	additiveShare, err := shamirShare.ToAdditive(shamirIdentities)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not derive additive share")
	}
	return additiveShare, nil
}

func (s *SigningKeyShare) UnmarshalJSON(data []byte) error {
	var temp struct {
		Share     json.RawMessage
		PublicKey json.RawMessage
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal signing key share")
	}
	share, err := curveutils.NewScalarFromJSON(temp.Share)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal share")
	}
	publicKey, err := curveutils.NewPointFromJSON(temp.PublicKey)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal public key")
	}
	s.Share = share
	s.PublicKey = publicKey
	return nil
}

func (s *SigningKeyShare) Equal(other *SigningKeyShare) bool {
	return s.Share != nil && s.Share.Equal(other.Share) && s.PublicKey != nil && s.PublicKey.Equal(other.PublicKey)
}

type PartialPublicKeys struct {
	PublicKey               curves.Point
	Shares                  ds.Map[types.SharingID, curves.Point]
	FeldmanCommitmentVector []curves.Point

	_ ds.Incomparable
}

func (p *PartialPublicKeys) IdentityBasedMapping(participants ds.Set[types.IdentityKey]) ds.Map[types.IdentityKey, curves.Point] {
	sharingConfig := types.DeriveSharingConfig(participants)
	identityBasedMap := hashmap.NewHashableHashMap[types.IdentityKey, curves.Point]()
	for sharingId, partialPublicKey := range p.Shares.Iter() {
		identityKey, exists := sharingConfig.Get(sharingId)
		if !exists {
			panic(errs.NewMissing("could not find identity key for sharing id %d", sharingId))
		}
		identityBasedMap.Put(identityKey, partialPublicKey)
	}
	return identityBasedMap
}

func (p *PartialPublicKeys) ToAdditive(protocol types.ThresholdSignatureProtocol, signers ds.Set[types.IdentityKey]) (ds.Map[types.IdentityKey, curves.Point], error) {
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	signersSharingIds := make([]uint, signers.Size())
	for i, signer := range signers.List() {
		sharingId, exists := sharingConfig.Reverse().Get(signer)
		if !exists {
			return nil, errs.NewFailed("invalid identity")
		}
		signersSharingIds[i] = uint(sharingId)
	}

	publicShares := hashmap.NewHashableHashMap[types.IdentityKey, curves.Point]()
	for signer := range signers.Iter() {
		sharingId, exists := sharingConfig.Reverse().Get(signer)
		if !exists {
			return nil, errs.NewMissing("could not find sharing id of %s", signer.String())
		}
		publicKeyShare, exists := p.Shares.Get(sharingId)
		if !exists {
			return nil, errs.NewFailed("invalid identity")
		}

		mySharingId, exists := sharingConfig.Reverse().Get(signer)
		if !exists {
			return nil, errs.NewFailed("invalid identity")
		}

		lagrangeCoefficient, err := (&shamir.Share{
			Id:    uint(mySharingId),
			Value: publicKeyShare.Curve().ScalarField().One(),
		}).ToAdditive(signersSharingIds)
		if err != nil {
			return nil, errs.WrapFailed(err, "invalid identity")
		}

		partialPublicKey := publicKeyShare.ScalarMul(lagrangeCoefficient)
		publicShares.Put(signer, partialPublicKey)
	}

	return publicShares, nil
}

func (p *PartialPublicKeys) Validate(protocol types.ThresholdProtocol) error {
	if p == nil {
		return errs.NewIsNil("receiver")
	}
	if p.PublicKey == nil {
		return errs.NewIsNil("public key")
	}
	if !p.PublicKey.IsInPrimeSubGroup() {
		return errs.NewValidation("Public Key not in the prime subgroup")
	}
	if len(p.FeldmanCommitmentVector) != int(protocol.Threshold()) {
		return errs.NewLength("feldman commitment vector length is invalid")
	}
	if p.Shares == nil {
		return errs.NewIsNil("shares map")
	}
	if !curveutils.AllPointsOfSameCurve(protocol.Curve(), p.PublicKey) {
		return errs.NewCurve("public key")
	}
	if !curveutils.AllPointsOfSameCurve(protocol.Curve(), p.Shares.Values()...) {
		return errs.NewCurve("shares map")
	}
	if !curveutils.AllPointsOfSameCurve(protocol.Curve(), p.FeldmanCommitmentVector...) {
		return errs.NewCurve("feldman commitment vector")
	}

	sharingIds := make([]curves.Scalar, protocol.TotalParties())
	partialPublicKeys := make([]curves.Point, protocol.TotalParties())
	for i := 0; i < int(protocol.TotalParties()); i++ {
		sharingId := types.SharingID(i + 1)
		sharingIds[i] = p.PublicKey.Curve().ScalarField().New(uint64(sharingId))
		partialPublicKey, exists := p.Shares.Get(sharingId)
		if !exists {
			return errs.NewMissing("partial public key doesn't exist for sharing id %d", sharingId)
		}
		partialPublicKeys[i] = partialPublicKey
	}
	evaluateAt := p.PublicKey.Curve().ScalarField().Zero() // because f(0) would be the private key which means interpolating in the exponent should give us the public key
	reconstructedPublicKey, err := lagrange.InterpolateInTheExponent(p.PublicKey.Curve(), sharingIds, partialPublicKeys, evaluateAt)
	if err != nil {
		return errs.WrapFailed(err, "could not interpolate partial public keys in the exponent")
	}
	if !reconstructedPublicKey.Equal(p.PublicKey) {
		return errs.NewVerification("reconstructed public key is incorrect")
	}
	return nil
}

func (p *PartialPublicKeys) MarshalJSON() ([]byte, error) {
	sharesStructure, ok := p.Shares.(*hashmap.ComparableHashMap[types.SharingID, curves.Point])
	if !ok {
		return nil, errs.NewType("shares map is not of the correct type")
	}
	out, err := json.Marshal(&struct {
		PublicKey               curves.Point
		Shares                  *hashmap.ComparableHashMap[types.SharingID, curves.Point]
		FeldmanCommitmentVector []curves.Point
	}{
		PublicKey:               p.PublicKey,
		Shares:                  sharesStructure,
		FeldmanCommitmentVector: p.FeldmanCommitmentVector,
	})
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal partial public keys")
	}
	return out, nil
}

func (p *PartialPublicKeys) UnmarshalJSON(data []byte) error {
	var temp struct {
		PublicKey               json.RawMessage
		Shares                  *hashmap.ComparableHashMap[types.SharingID, json.RawMessage]
		FeldmanCommitmentVector []json.RawMessage
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal partial public keys")
	}
	publicKey, err := curveutils.NewPointFromJSON(temp.PublicKey)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal public key")
	}

	unmarshaledShares := hashmap.NewComparableHashMap[types.SharingID, curves.Point]()
	for sharingId, rawPoint := range temp.Shares.Iter() {
		point, err := curveutils.NewPointFromJSON(rawPoint)
		if err != nil {
			return errs.WrapSerialisation(err, "could not unmarshal partial public key")
		}
		unmarshaledShares.Put(sharingId, point)
	}

	feldmanVector := make([]curves.Point, len(temp.FeldmanCommitmentVector))
	for i, rawPoint := range temp.FeldmanCommitmentVector {
		point, err := curveutils.NewPointFromJSON(rawPoint)
		if err != nil {
			return errs.WrapSerialisation(err, "could not unmarshal feldman commitment vector")
		}
		feldmanVector[i] = point
	}
	p.PublicKey = publicKey
	p.Shares = unmarshaledShares
	p.FeldmanCommitmentVector = feldmanVector
	return nil
}

func (p *PartialPublicKeys) Equal(other *PartialPublicKeys) bool {
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

type PreProcessingMaterial[PrivateType any, PreSignatureType any] struct {
	PreSigners      ds.Set[types.IdentityKey]
	PrivateMaterial PrivateType
	PreSignature    PreSignatureType

	_ ds.Incomparable
}
