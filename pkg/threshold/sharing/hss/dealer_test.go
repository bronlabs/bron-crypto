package hss_test

import (
	crand "crypto/rand"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/hss"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_HierarchicalSecretSharing(t *testing.T) {
	prng := crand.Reader
	field := k256.NewScalarField()
	secret, err := field.Random(prng)
	require.NoError(t, err)

	shares, err := hss.Share(secret, []uint{1, 2, 3}, []uint{1, 2, 3}, prng)
	require.NoError(t, err)
	require.Len(t, shares, 6)
	// share  0       is L0
	// shares 1, 2    is L1
	// shares 3, 4, 5 is L2

	// L2 + L2 + L2 SHOULD NOT reconstruct secret
	_, err = hss.Reconstruct([]*hss.HierarchicalShare{shares[3], shares[4], shares[5]}...)
	require.Error(t, err)

	// L2 + L2 + L1 SHOULD NOT reconstruct secret
	_, err = hss.Reconstruct([]*hss.HierarchicalShare{shares[1], shares[4], shares[5]}...)
	require.Error(t, err)

	// L2 + L2 + L0 SHOULD NOT reconstruct secret
	_, err = hss.Reconstruct([]*hss.HierarchicalShare{shares[0], shares[4], shares[5]}...)
	require.Error(t, err)

	// L2 + L1 + L0 SHOULD reconstruct secret
	reconstructed, err := hss.Reconstruct([]*hss.HierarchicalShare{shares[0], shares[1], shares[3]}...)
	require.NoError(t, err)
	require.True(t, reconstructed.Equal(secret))

	// L1 + L1 + L0 SHOULD reconstruct secret as well
	reconstructed, err = hss.Reconstruct([]*hss.HierarchicalShare{shares[0], shares[1], shares[2]}...)
	require.NoError(t, err)
	require.True(t, reconstructed.Equal(secret))
}
