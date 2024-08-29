package replicated_test

import (
	crand "crypto/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/replicated"
)

func Test_ReplicatedSharing(t *testing.T) {
	t.Parallel()

	// create parties identifiers first
	alice := replicated.PartyNew(1)
	bob := replicated.PartyNew(2)
	charlie := replicated.PartyNew(3)
	darcy := replicated.PartyNew(4)

	// create `(alice & bob) | (charlie & darcy)` access structure
	accessStructure := replicated.AccessStructureNew((alice.And(bob)).Or(charlie.And(darcy)))

	secret, err := k256.NewScalarField().Random(crand.Reader)
	require.NoError(t, err)

	shares, err := accessStructure.Share(secret, crand.Reader)
	require.NoError(t, err)

	aliceShare := shares[0]
	bobShare := shares[1]
	charlieShare := shares[2]
	darcyShare := shares[3]

	// alice and bob (or any superset thereof) CAN reconstruct
	t.Run("alice & bob", func(t *testing.T) {
		t.Parallel()
		aliceAndBob, err := accessStructure.Combine(aliceShare, bobShare)
		require.NoError(t, err)
		require.NotNil(t, aliceAndBob)
		require.True(t, aliceAndBob.Equal(secret))
	})

	// charlie and darcy (or any superset thereof) CAN reconstruct
	t.Run("charlie & darcy", func(t *testing.T) {
		t.Parallel()
		charlieAndDarcy, err := accessStructure.Combine(charlieShare, darcyShare)
		require.NoError(t, err)
		require.NotNil(t, charlieAndDarcy)
		require.True(t, charlieAndDarcy.Equal(secret))
	})

	// alice and charlie CANNOT reconstruct
	t.Run("alice & charlie", func(t *testing.T) {
		t.Parallel()
		_, err = accessStructure.Combine(aliceShare, charlieShare)
		require.Error(t, err)
		require.True(t, strings.Contains(err.Error(), "not enough sub-shares"))
	})

	// alice and darcy CANNOT reconstruct
	t.Run("alice & darcy", func(t *testing.T) {
		t.Parallel()
		_, err = accessStructure.Combine(aliceShare, darcyShare)
		require.Error(t, err)
		require.True(t, strings.Contains(err.Error(), "not enough sub-shares"))
	})

	// bob and charlie CANNOT reconstruct
	t.Run("bob & charlie", func(t *testing.T) {
		t.Parallel()
		_, err = accessStructure.Combine(bobShare, charlieShare)
		require.Error(t, err)
		require.True(t, strings.Contains(err.Error(), "not enough sub-shares"))
	})

	// bob and darcy CANNOT reconstruct
	t.Run("bob & darcy", func(t *testing.T) {
		t.Parallel()
		_, err = accessStructure.Combine(bobShare, darcyShare)
		require.Error(t, err)
		require.True(t, strings.Contains(err.Error(), "not enough sub-shares"))
	})
}
