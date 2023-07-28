package test_utils

import (
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/datastructures/hashset"
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
	_, err = hashset.NewHashSet([]integration.IdentityKey{identityAlice, identityBob})
	assert.True(t, errs.IsDuplicate(err))
}

func TestCheckExistIdentity(t *testing.T) {
	cipherSuite := &integration.CipherSuite{
		Curve: curves.ED25519(),
		Hash:  sha3.New256,
	}
	identityAlice, err := MakeIdentity(cipherSuite, curves.ED25519().Scalar.Hash([]byte{1}), nil)
	identityBob, err := MakeIdentity(cipherSuite, curves.ED25519().Scalar.Hash([]byte{2}), nil)
	s, err := hashset.NewHashSet([]integration.IdentityKey{identityAlice})
	assert.NoError(t, err)
	assert.True(t, s.Size() == 1)
	_, found := s.Get(identityAlice)
	assert.True(t, found)
	_, found = s.Get(identityBob)
	assert.False(t, found)
}
