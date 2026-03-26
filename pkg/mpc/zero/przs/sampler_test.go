package przs_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curve25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/zero/przs"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	testHappyPath(t, k256.NewCurve(), 3)
	testHappyPath(t, p256.NewScalarField(), 4)
	testHappyPath(t, curve25519.NewScalarField(), 5)
}

func testHappyPath[G algebra.GroupElement[G]](tb testing.TB, group algebra.FiniteGroup[G], n int) {
	tb.Helper()

	prng := pcg.NewRandomised()
	quorum := sharing.NewOrdinalShareholderSet(uint(n))
	ctxs := session_testutils.MakeRandomContexts(tb, quorum, prng)

	sum := group.OpIdentity()
	for _, ctx := range ctxs {
		share, err := przs.SampleZeroShare(ctx, group)
		require.NoError(tb, err)
		sum = sum.Op(share.Value())
	}
	require.True(tb, sum.IsOpIdentity())

	sum = group.OpIdentity()
	for _, ctx := range ctxs {
		share, err := przs.SampleZeroShare(ctx, group)
		require.NoError(tb, err)
		sum = sum.Op(share.Value())
	}
	require.True(tb, sum.IsOpIdentity())
}
