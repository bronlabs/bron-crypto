package testutils

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton/pkg/base/types/integration"
)

// TODO: we can't check generic is nil at the moment unless we use reflection. Hopefully in future Go update we can do that
//func TestCheckNilParticipant(t *testing.T) {
//	_, err := set.NewImmutableComparableHashmap([]integration.IdentityKey{nil})
//	assert.True(t, errs.IsIsNil(err))
//}

func TestCheckExistIdentity(t *testing.T) {
	cipherSuite := &integration.CipherSuite{
		Curve: edwards25519.New(),
		Hash:  sha3.New256,
	}
	identityAlice, err := MakeIdentity(cipherSuite, edwards25519.New().Scalar().Hash([]byte{1}))
	require.NoError(t, err)
	identityBob, err := MakeIdentity(cipherSuite, edwards25519.New().Scalar().Hash([]byte{2}))
	require.NoError(t, err)
	s := hashset.NewHashSet([]integration.IdentityKey{identityAlice})
	require.NoError(t, err)
	require.True(t, s.Len() == 1)
	_, found := s.Get(identityAlice)
	require.True(t, found)
	_, found = s.Get(identityBob)
	require.False(t, found)
}
