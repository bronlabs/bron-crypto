package tbls

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
)

type PublicMaterial[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	publicKey         *bls.PublicKey[PK, PKFE, SG, SGFE, E, S]
	accessStructure   *feldman.AccessStructure
	fv                *feldman.VerificationVector[PK, S]
	partialPublicKeys ds.Map[sharing.ID, *bls.PublicKey[PK, PKFE, SG, SGFE, E, S]]
}

func (spm *PublicMaterial[PK, PKFE, SG, SGFE, E, S]) PublicKey() *bls.PublicKey[PK, PKFE, SG, SGFE, E, S] {
	if spm == nil {
		return nil
	}
	return spm.publicKey
}

func (spm *PublicMaterial[PK, PKFE, SG, SGFE, E, S]) AccessStructure() *feldman.AccessStructure {
	if spm == nil {
		return nil
	}
	return spm.accessStructure
}

func (spm *PublicMaterial[PK, PKFE, SG, SGFE, E, S]) PartialPublicKeys() ds.Map[sharing.ID, *bls.PublicKey[PK, PKFE, SG, SGFE, E, S]] {
	if spm == nil {
		return nil
	}
	return spm.partialPublicKeys
}

func (spm *PublicMaterial[PK, PKFE, SG, SGFE, E, S]) VerificationVector() *feldman.VerificationVector[PK, S] {
	if spm == nil {
		return nil
	}
	return spm.fv
}

func (spm *PublicMaterial[PK, PKFE, SG, SGFE, E, S]) Equal(other *PublicMaterial[PK, PKFE, SG, SGFE, E, S]) bool {
	if spm == nil || other == nil {
		return spm == other
	}
	for id, pk := range spm.partialPublicKeys.Iter() {
		otherPk, exists := other.partialPublicKeys.Get(id)
		if !exists || !pk.Equal(otherPk) {
			return false
		}
	}
	return spm.publicKey.Equal(other.publicKey) &&
		spm.accessStructure.Equal(other.accessStructure)
}

func (spm *PublicMaterial[PK, PKFE, SG, SGFE, E, S]) HashCode() base.HashCode {
	if spm == nil {
		return 0
	}
	return spm.publicKey.HashCode()
}

type Shard[
	PK curves.PairingFriendlyPoint[PK, PKFE, SG, SGFE, E, S], PKFE algebra.FieldElement[PKFE],
	SG curves.PairingFriendlyPoint[SG, SGFE, PK, PKFE, E, S], SGFE algebra.FieldElement[SGFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
] struct {
	share *feldman.Share[S]
	PublicMaterial[PK, PKFE, SG, SGFE, E, S]
}

func (s *Shard[PK, PKFE, SG, SGFE, E, S]) Share() *feldman.Share[S] {
	if s == nil {
		return nil
	}
	return s.share
}

func (s *Shard[PK, PKFE, SG, SGFE, E, S]) Equal(other *Shard[PK, PKFE, SG, SGFE, E, S]) bool {
	if s == nil && other == nil {
		return s == other
	}
	return (s.share.Equal(other.share) &&
		s.PublicMaterial.Equal(&other.PublicMaterial))
}

func (s *Shard[PK, PKFE, SG, SGFE, E, S]) PublicKeyMaterial() *PublicMaterial[PK, PKFE, SG, SGFE, E, S] {
	if s == nil {
		return nil
	}
	return &PublicMaterial[PK, PKFE, SG, SGFE, E, S]{
		publicKey:         s.publicKey.Clone(),
		accessStructure:   s.accessStructure.Clone(),
		partialPublicKeys: s.partialPublicKeys.Clone(),
	}
}

func (s *Shard[PK, PKFE, SG, SGFE, E, S]) HashCode() base.HashCode {
	if s == nil {
		return 0
	}
	return s.share.HashCode() ^ s.publicKey.HashCode()
}

func (s *Shard[PK, PKFE, SG, SGFE, E, S]) AsBLSPrivateKey() (*bls.PrivateKey[PK, PKFE, SG, SGFE, E, S], error) {
	if s == nil {
		return nil, errs.NewIsNil("Shard is nil")
	}
	out, err := bls.NewPrivateKey(s.publicKey.Group(), s.share.Value())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create BLS private key from shard")
	}
	return out, nil
}

func NewShortKeyShard[
	P1 curves.PairingFriendlyPoint[P1, FE1, P2, FE2, E, S], FE1 algebra.FieldElement[FE1],
	P2 curves.PairingFriendlyPoint[P2, FE2, P1, FE1, E, S], FE2 algebra.FieldElement[FE2],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](

	share *feldman.Share[S],
	publicKey *bls.PublicKey[P1, FE1, P2, FE2, E, S],
	vector feldman.VerificationVector[P1, S],
	accessStructure *feldman.AccessStructure,
) (*Shard[P1, FE1, P2, FE2, E, S], error) {
	if share == nil {
		return nil, errs.NewIsNil("share")
	}
	if publicKey == nil {
		return nil, errs.NewIsNil("publicKey")
	}
	if accessStructure == nil {
		return nil, errs.NewIsNil("accessStructure")
	}
	if vector == nil {
		return nil, errs.NewIsNil("verification vector")
	}
	if !publicKey.IsShort() {
		return nil, errs.NewType("public key is not a short key variant")
	}
	sf, ok := share.Value().Structure().(algebra.PrimeField[S])
	if !ok {
		return nil, errs.NewType("share value structure is not a prime field")
	}
	partialPublicKeyValues, err := gennaro.ComputePartialPublicKey(sf, share, vector, accessStructure)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to compute partial public keys from share")
	}
	partialPublicKeys := hashmap.NewComparable[sharing.ID, *bls.PublicKey[P1, FE1, P2, FE2, E, S]]()
	for id, value := range partialPublicKeyValues.Iter() {
		pk, err := bls.NewPublicKey(value)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to create public key for party %d", id)
		}
		partialPublicKeys.Put(id, pk)
	}
	return &Shard[P1, FE1, P2, FE2, E, S]{
		share: share,
		PublicMaterial: PublicMaterial[P1, FE1, P2, FE2, E, S]{
			publicKey:         publicKey,
			accessStructure:   accessStructure,
			partialPublicKeys: partialPublicKeys.Freeze(),
		},
	}, nil
}

func NewLongKeyShard[
	P1 curves.PairingFriendlyPoint[P1, FE1, P2, FE2, E, S], FE1 algebra.FieldElement[FE1],
	P2 curves.PairingFriendlyPoint[P2, FE2, P1, FE1, E, S], FE2 algebra.FieldElement[FE2],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
](
	share *feldman.Share[S],
	publicKey *bls.PublicKey[P2, FE2, P1, FE1, E, S],
	vector feldman.VerificationVector[P2, S],
	accessStructure *feldman.AccessStructure,
) (*Shard[P2, FE2, P1, FE1, E, S], error) {
	if share == nil {
		return nil, errs.NewIsNil("share")
	}
	if publicKey == nil {
		return nil, errs.NewIsNil("publicKey")
	}
	if accessStructure == nil {
		return nil, errs.NewIsNil("accessStructure")
	}
	if vector == nil {
		return nil, errs.NewIsNil("verification vector")
	}
	if publicKey.IsShort() {
		return nil, errs.NewType("public key is not a long key variant")
	}
	sf, ok := share.Value().Structure().(algebra.PrimeField[S])
	if !ok {
		return nil, errs.NewType("share value structure is not a prime field")
	}
	partialPublicKeyValues, err := gennaro.ComputePartialPublicKey(sf, share, vector, accessStructure)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to compute partial public keys from share")
	}
	partialPublicKeys := hashmap.NewComparable[sharing.ID, *bls.PublicKey[P2, FE2, P1, FE1, E, S]]()
	for id, value := range partialPublicKeyValues.Iter() {
		pk, err := bls.NewPublicKey(value)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to create public key for party %d", id)
		}
		partialPublicKeys.Put(id, pk)
	}
	return &Shard[P2, FE2, P1, FE1, E, S]{
		share: share,
		PublicMaterial: PublicMaterial[P2, FE2, P1, FE1, E, S]{
			publicKey:         publicKey,
			accessStructure:   accessStructure,
			partialPublicKeys: partialPublicKeys.Freeze(),
		},
	}, nil
}
