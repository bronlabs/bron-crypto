package lindell17

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
)

const (
	// Threshold Lindell 2017 threshold (always 2).
	Threshold = 2
)

var _ tsignatures.Shard = (*Shard)(nil)

type Shard struct {
	SigningKeyShare         *tsignatures.SigningKeyShare
	PublicKeyShares         *tsignatures.PartialPublicKeys
	PaillierSecretKey       *paillier.SecretKey
	PaillierPublicKeys      ds.HashMap[types.IdentityKey, *paillier.PublicKey]
	PaillierEncryptedShares ds.HashMap[types.IdentityKey, *paillier.CipherText]

	_ ds.Incomparable
}

type PartialSignature struct {
	C3 *paillier.CipherText

	_ ds.Incomparable
}

type PreSignature struct {
	K    curves.Scalar
	BigR ds.HashMap[types.IdentityKey, curves.Point]

	_ ds.Incomparable
}

func (ps *PreSignature) Validate(protocol types.ThresholdSignatureProtocol) error {
	if ps == nil {
		return errs.NewIsNil("receiver")
	}
	if ps.K == nil {
		return errs.NewIsNil("K")
	}
	if !curveutils.AllScalarsOfSameCurve(protocol.Curve(), ps.K) {
		return errs.NewCurve("K")
	}
	if ps.BigR == nil {
		return errs.NewIsNil("BigR")
	}
	if !curveutils.AllPointsOfSameCurve(protocol.Curve(), ps.BigR.Values()...) {
		return errs.NewCurve("BigR")
	}
	bigRKeys := hashset.NewHashableHashSet(ps.BigR.Keys()...)
	if !bigRKeys.Equal(protocol.Participants()) {
		return errs.NewMembership("set of people with BigR is not the same as participants")
	}
	bigRValues := hashset.NewHashableHashSet(ps.BigR.Values()...)
	if bigRValues.Size() != len(ps.BigR.Values()) {
		return errs.NewMembership("not all big R values are unique")
	}
	return nil
}

type PreSignatureBatch []PreSignature

func (psb PreSignatureBatch) Validate(protocol types.ThresholdSignatureProtocol) error {
	if psb == nil {
		return errs.NewIsNil("receiver")
	}
	Rs := hashset.NewHashableHashSet[curves.Point]()
	for i, ps := range psb {
		if err := ps.Validate(protocol); err != nil {
			return errs.WrapValidation(err, "presignature index %d", i)
		}
		Rs.Merge(ps.BigR.Values()...)
	}
	if Rs.Size() != protocol.Participants().Size()*len(psb) {
		return errs.NewValue("there exist a duplicate R across the batch")
	}
	return nil
}

func (s *Shard) Validate(protocol types.ThresholdSignatureProtocol, holderIdentityKey types.IdentityKey, recomputeCached bool) error {
	if s == nil {
		return errs.NewIsNil("receiver")
	}
	if err := s.SigningKeyShare.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "invalid signing key share")
	}
	if err := s.PublicKeyShares.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "invalid public key shares")
	}
	if err := s.PaillierSecretKey.Validate(recomputeCached); err != nil {
		return errs.WrapValidation(err, "paillier secret key")
	}
	if s.PaillierPublicKeys == nil {
		return errs.NewIsNil("paillier public keys")
	}
	paillierPublicKeyHolders := hashset.NewHashableHashSet(s.PaillierPublicKeys.Keys()...)
	if delta := paillierPublicKeyHolders.SymmetricDifference(protocol.Participants()); delta.Size() != 1 || !delta.Contains(holderIdentityKey) {
		return errs.NewMembership("paillier public keys")
	}
	if s.PaillierEncryptedShares == nil {
		return errs.NewIsNil("paillier encrypted share")
	}
	paillierEncryptedShareHolders := hashset.NewHashableHashSet(s.PaillierEncryptedShares.Keys()...)
	if delta := paillierEncryptedShareHolders.SymmetricDifference(protocol.Participants()); delta.Size() != 1 || !delta.Contains(holderIdentityKey) {
		return errs.NewMembership("paillier encrypted shares")
	}
	if !paillierEncryptedShareHolders.Equal(paillierPublicKeyHolders) {
		return errs.NewMembership("number of paillier public keys != number of encrypted paillier ciphertexts")
	}
	for pair := range s.PaillierEncryptedShares.Iter() {
		id := pair.Key
		esk := pair.Value
		pk, exists := s.PaillierPublicKeys.Get(id)
		if !exists {
			return errs.NewMissing("paillier public key for %x", id.PublicKey())
		}
		if err := pk.Validate(recomputeCached); err != nil {
			return errs.WrapValidation(err, "invalid public key %x", id.PublicKey())
		}
		if err := esk.Validate(pk); err != nil {
			return errs.WrapValidation(err, "invalid public key %x", id.PublicKey())
		}
	}
	return nil
}
func (s *Shard) SecretShare() curves.Scalar {
	return s.SigningKeyShare.Share
}

func (s *Shard) PublicKey() curves.Point {
	return s.SigningKeyShare.PublicKey
}

func (s *Shard) PartialPublicKeys() ds.HashMap[types.IdentityKey, curves.Point] {
	return s.PublicKeyShares.Shares
}

func (s *Shard) FeldmanCommitmentVector() []curves.Point {
	return s.PublicKeyShares.FeldmanCommitmentVector
}
