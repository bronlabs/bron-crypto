package test_utils

import (
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/datastructures/comparableelement"
	"github.com/copperexchange/crypto-primitives-go/pkg/datastructures/hashmap"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
)

// TODO: we can't check generic is nil at the moment unless we use reflection. Hopefully in future Go update we can do that
//func TestCheckNilParticipant(t *testing.T) {
//	_, err := set.NewImmutableComparableHashmap([]integration.IdentityKey{nil})
//	assert.True(t, errs.IsIsNil(err))
//}

func TestCheckDuplicateParticipantByPubkey(t *testing.T) {
	cipherSuite := &integration.CipherSuite{
		Curve: curves.ED25519(),
		Hash:  sha3.New256,
	}
	identityAlice, err := MakeIdentity(cipherSuite, curves.ED25519().Scalar.Hash([]byte{1}), nil)
	identityBob, err := MakeIdentity(cipherSuite, curves.ED25519().Scalar.Hash([]byte{1}), nil)
	_, err = hashmap.NewHashmap([]integration.IdentityKey{identityAlice, identityBob})
	assert.True(t, errs.IsDuplicate(err))
}

func TestCompareIdentity(t *testing.T) {
	cipherSuite := &integration.CipherSuite{
		Curve: curves.ED25519(),
		Hash:  sha3.New256,
	}
	identityAlice, _ := MakeIdentity(cipherSuite, curves.ED25519().Scalar.Hash([]byte{1}), nil)
	identitySameAlice, _ := MakeIdentity(cipherSuite, curves.ED25519().Scalar.Hash([]byte{1}), nil)
	identityBob, _ := MakeIdentity(cipherSuite, curves.ED25519().Scalar.Hash([]byte{2}), nil)
	assert.True(t, comparableelement.Compare(identityAlice, identityBob) > 0)
	assert.True(t, comparableelement.Compare(identityBob, identityAlice) < 0)
	assert.True(t, comparableelement.Compare(identityAlice, identitySameAlice) == 0)
}

func TestSortIdentities(t *testing.T) {
	cipherSuite := &integration.CipherSuite{
		Curve: curves.ED25519(),
		Hash:  sha3.New256,
	}
	identityAlice, _ := MakeIdentity(cipherSuite, curves.ED25519().Scalar.Hash([]byte{1}), nil)
	identityBob, _ := MakeIdentity(cipherSuite, curves.ED25519().Scalar.Hash([]byte{2}), nil)
	sorted, err := comparableelement.SortNoDuplicate([]comparableelement.ComparableElement{identityBob, identityAlice})
	assert.NoError(t, err)
	assert.Equal(t, sorted[0].HashCode(), identityBob.HashCode())
	assert.Equal(t, sorted[1].HashCode(), identityAlice.HashCode())
}

func TestSortDuplicateIdentities(t *testing.T) {
	cipherSuite := &integration.CipherSuite{
		Curve: curves.ED25519(),
		Hash:  sha3.New256,
	}
	identityAlice, _ := MakeIdentity(cipherSuite, curves.ED25519().Scalar.Hash([]byte{1}), nil)
	identityBob, _ := MakeIdentity(cipherSuite, curves.ED25519().Scalar.Hash([]byte{1}), nil)
	_, err := comparableelement.SortNoDuplicate([]comparableelement.ComparableElement{identityBob, identityAlice})
	assert.True(t, errs.IsDuplicate(err))
}

func TestCheckExistIdentity(t *testing.T) {
	cipherSuite := &integration.CipherSuite{
		Curve: curves.ED25519(),
		Hash:  sha3.New256,
	}
	identityAlice, err := MakeIdentity(cipherSuite, curves.ED25519().Scalar.Hash([]byte{1}), nil)
	identityBob, err := MakeIdentity(cipherSuite, curves.ED25519().Scalar.Hash([]byte{2}), nil)
	s, err := hashmap.NewHashmap([]integration.IdentityKey{identityAlice})
	assert.NoError(t, err)
	assert.True(t, hashmap.Size(s) == 1)
	_, found := hashmap.Get(s, identityAlice)
	assert.True(t, found)
	_, found = hashmap.Get(s, identityBob)
	assert.False(t, found)
}
