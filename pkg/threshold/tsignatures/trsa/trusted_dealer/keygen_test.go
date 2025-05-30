package trusted_dealer_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/rep23"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa/trusted_dealer"
)

const (
	threshold = 2
	total     = 3
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	identities, err := testutils.MakeDeterministicTestIdentities(total)
	require.NoError(t, err)

	protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, threshold)
	require.NoError(t, err)

	publicKey, shards, err := trusted_dealer.Keygen(protocol, prng)
	require.NoError(t, err)
	shardValues := shards.Values()

	t.Run("public keys match", func(t *testing.T) {
		t.Parallel()
		for i, s := range shardValues {
			require.Equal(t, uint64(trsa.RsaE), s.E)
			require.NotEqual(t, s.N1.Bytes(), s.N2.Bytes())
			require.Equal(t, publicKey, s.PublicKey())
			if i > 0 {
				require.Equal(t, shardValues[i-1].N1.Bytes(), s.N1.Bytes())
				require.Equal(t, shardValues[i-1].N2.Bytes(), s.N2.Bytes())
				require.Equal(t, shardValues[i-1].PublicKey(), s.PublicKey())
			}
		}
	})

	t.Run("secret keys match public keys", func(t *testing.T) {
		t.Parallel()
		dealer := rep23.NewIntScheme()

		d1Shares := sliceutils.Map(shardValues, func(s *trsa.Shard) *rep23.IntShare { return s.D1Share })
		d1, err := dealer.Open(d1Shares...)
		require.NoError(t, err)
		baseBig, err := crand.Int(prng, shardValues[0].N1.Big())
		require.NoError(t, err)
		base := new(saferith.Nat).SetBig(baseBig, shardValues[0].N1.BitLen())
		check := new(saferith.Nat).ExpI(base, d1, shardValues[0].N1)
		check.Exp(check, new(saferith.Nat).SetUint64(trsa.RsaE), shardValues[0].N1)
		require.Equal(t, saferith.Choice(1), base.Eq(check))

		d2Shares := sliceutils.Map(shardValues, func(s *trsa.Shard) *rep23.IntShare { return s.D2Share })
		d2, err := dealer.Open(d2Shares...)
		require.NoError(t, err)
		baseBig, err = crand.Int(prng, shardValues[0].N2.Big())
		require.NoError(t, err)
		base = new(saferith.Nat).SetBig(baseBig, shardValues[0].N2.BitLen())
		check = new(saferith.Nat).ExpI(base, d2, shardValues[0].N2)
		check.Exp(check, new(saferith.Nat).SetUint64(trsa.RsaE), shardValues[0].N2)
		require.Equal(t, saferith.Choice(1), base.Eq(check))
	})
}
