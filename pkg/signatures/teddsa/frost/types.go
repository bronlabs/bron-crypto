package frost

import (
	"sort"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/pkg/errors"
)

type SigningKeyShare struct {
	Share     curves.Scalar
	PublicKey curves.Point
}

func (s *SigningKeyShare) Validate() error {
	if s == nil {
		return errors.New("signing key share is nil")
	}
	if s.Share.IsZero() {
		return errors.New("share can't be zero")
	}
	if s.PublicKey.IsIdentity() {
		return errors.New("public key can't be at infinity")
	}
	if !s.PublicKey.IsOnCurve() {
		return errors.New("public key is not on curve")
	}
	return nil
}

type PublicKeyShares struct {
	Curve     *curves.Curve
	PublicKey curves.Point
	SharesMap map[integration.IdentityKey]curves.Point
}

// TODO: write down validation (lambda trick)

// func (p *PublicKeyShares) Validate() error {
// 	derivedPublicKey := p.Curve.Point.Identity()
// 	for _, share := range p.SharesMap {
// 		derivedPublicKey = derivedPublicKey.Add(share)
// 	}
// 	if !derivedPublicKey.Equal(p.PublicKey) {
// 		return errors.New("public key shares can't be combined to the entire public key")
// 	}
// 	return nil
// }

type PartialSignature struct {
	Zi curves.Scalar
}

type Signature struct {
	R curves.Point
	Z curves.Scalar
}

func DeriveShamirIds(myIdentityKey integration.IdentityKey, identityKeys []integration.IdentityKey) (map[int]integration.IdentityKey, int, error) {
	result := map[int]integration.IdentityKey{}
	myShamirId := -1

	mySerializedIdentityKey, err := integration.SerializePublicKey(myIdentityKey.PublicKey())
	if err != nil {
		return nil, myShamirId, errors.Wrap(err, "couldn't serialize my identity public key")
	}

	serializedIdentityKeyToIdentityKey := map[string]integration.IdentityKey{}
	serializedIdentityKeys := make([]string, len(identityKeys))

	for i, identityKey := range identityKeys {
		serialized, err := integration.SerializePublicKey(identityKey.PublicKey())
		if err != nil {
			return nil, myShamirId, errors.Wrap(err, "couldn't serialize public key")
		}
		serializedIdentityKeyToIdentityKey[serialized] = identityKey
		serializedIdentityKeys[i] = serialized
	}
	sort.Strings(serializedIdentityKeys)
	for shamirIdMinusOne, serializedIdentityKey := range serializedIdentityKeys {
		identityKey, exists := serializedIdentityKeyToIdentityKey[serializedIdentityKey]
		if !exists {
			return nil, myShamirId, errors.Errorf("identity key %s does not exist", serializedIdentityKey)
		}
		result[shamirIdMinusOne+1] = identityKey
		if serializedIdentityKey == mySerializedIdentityKey {
			myShamirId = shamirIdMinusOne + 1
		}
	}
	if myShamirId == -1 {
		return nil, myShamirId, errors.New("couldn't find my shamir Id")
	}
	return result, myShamirId, nil
}
