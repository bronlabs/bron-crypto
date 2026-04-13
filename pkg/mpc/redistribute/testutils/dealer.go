package testutils

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/stretchr/testify/require"
)

func Deal[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](tb testing.TB, accessStructure accessstructures.Monotone, group algebra.PrimeGroup[G, S], secret S) map[sharing.ID]*mpc.BaseShard[G, S] {
	tb.Helper()

	vss, err := feldman.NewScheme(group, accessStructure)
	require.NoError(tb, err)
	kwSecret := kw.NewSecret(secret)
	dealOut, err := vss.Deal(kwSecret, pcg.NewRandomised())
	require.NoError(tb, err)

	result := make(map[sharing.ID]*mpc.BaseShard[G, S])
	for id := range accessStructure.Shareholders().Iter() {
		share, ok := dealOut.Shares().Get(id)
		require.True(tb, ok)

		baseShard, err := mpc.NewBaseShard(share, dealOut.VerificationMaterial(), vss.MSP())
		require.NoError(tb, err)
		result[id] = baseShard
	}

	return result
}
