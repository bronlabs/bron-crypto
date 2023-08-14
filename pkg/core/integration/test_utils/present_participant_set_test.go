package test_utils

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/core/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashset"
)

// TODO: we can't check generic is nil at the moment unless we use reflection. Hopefully in future Go update we can do that
//func TestCheckNilParticipant(t *testing.T) {
//	_, err := set.NewImmutableComparableHashmap([]integration.IdentityKey{nil})
//	assert.True(t, errs.IsIsNil(err))
//}

func TestCheckDuplicateParticipantByPubkey(t *testing.T) {
	cipherSuite := &integration.CipherSuite{
		Curve: edwards25519.New(),
		Hash:  sha3.New256,
	}
	identityAlice, err := MakeIdentity(cipherSuite, edwards25519.New().Scalar().Hash([]byte{1}), nil)
	require.NoError(t, err)
	identityBob, err := MakeIdentity(cipherSuite, edwards25519.New().Scalar().Hash([]byte{1}), nil)
	require.NoError(t, err)
	_, err = hashset.NewHashSet([]integration.IdentityKey{identityAlice, identityBob})
	require.True(t, errs.IsDuplicate(err))
}

func TestCheckExistIdentity(t *testing.T) {
	cipherSuite := &integration.CipherSuite{
		Curve: edwards25519.New(),
		Hash:  sha3.New256,
	}
	identityAlice, err := MakeIdentity(cipherSuite, edwards25519.New().Scalar().Hash([]byte{1}), nil)
	require.NoError(t, err)
	identityBob, err := MakeIdentity(cipherSuite, edwards25519.New().Scalar().Hash([]byte{2}), nil)
	require.NoError(t, err)
	s, err := hashset.NewHashSet([]integration.IdentityKey{identityAlice})
	require.NoError(t, err)
	require.True(t, s.Size() == 1)
	_, found := s.Get(identityAlice)
	require.True(t, found)
	_, found = s.Get(identityBob)
	require.False(t, found)
}
