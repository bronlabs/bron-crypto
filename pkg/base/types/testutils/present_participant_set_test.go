package testutils

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

func TestCheckExistIdentity(t *testing.T) {
	cipherSuite, err := MakeSignatureProtocol(edwards25519.NewCurve(), sha3.New256)
	require.NoError(t, err)
	sk1, err := edwards25519.NewCurve().ScalarField().Hash([]byte{1})
	require.NoError(t, err)
	sk2, err := edwards25519.NewCurve().ScalarField().Hash([]byte{2})
	require.NoError(t, err)
	identityAlice, err := MakeTestIdentity(cipherSuite, sk1)
	require.NoError(t, err)
	identityBob, err := MakeTestIdentity(cipherSuite, sk2)
	require.NoError(t, err)
	s := hashset.NewHashableHashSet([]types.IdentityKey{identityAlice}...)
	require.NoError(t, err)
	require.True(t, s.Size() == 1)
	found := s.Contains(identityAlice)
	require.True(t, found)
	found = s.Contains(identityBob)
	require.False(t, found)
}
