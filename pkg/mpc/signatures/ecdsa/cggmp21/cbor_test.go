package cggmp21_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
)

func TestAuxInfoCBORRoundTrip(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	localPaillier, err := paillier.SampleBlumSecretKey(64, prng)
	require.NoError(t, err)
	peerPaillier, err := paillier.SampleBlumSecretKey(64, prng)
	require.NoError(t, err)
	localRingPedersen, err := intcom.SampleTrapdoorKey(64, prng)
	require.NoError(t, err)
	peerRingPedersen, err := intcom.SampleTrapdoorKey(64, prng)
	require.NoError(t, err)
	refreshID := make([]byte, base.CollisionResistanceBytesCeil)
	_, err = io.ReadFull(prng, refreshID)
	require.NoError(t, err)

	info, err := cggmp21.NewAuxInfo(
		localPaillier,
		map[sharing.ID]*paillier.PublicKey{2: peerPaillier.Public()},
		localRingPedersen,
		map[sharing.ID]*intcom.CommitmentKey{2: peerRingPedersen.Export()},
		refreshID,
	)
	require.NoError(t, err)

	roundTripped := ntu.CBORRoundTrip(t, info)
	require.True(t, info.Equal(roundTripped))
}
