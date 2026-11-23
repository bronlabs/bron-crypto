package rvole_mrr21_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/rvole"
	rvole_mrr21 "github.com/bronlabs/bron-crypto/pkg/mpc/rvole/mrr21"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
)

// BenchmarkRVOLE measures one ℓ = 2 random VOLE on base OTs alone, both sides
// computed sequentially: ξ = 1792 one-round-trip MRR21 OTs with 256-bit
// messages, one per row.
func BenchmarkRVOLE(b *testing.B) {
	const l = 2
	prng := pcg.NewRandomised()
	suite, err := rvole.NewSuite(l, k256.NewCurve())
	require.NoError(b, err)
	a := randomInput(b, l)
	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		ctxs := session_testutils.MakeRandomContexts(b, hashset.NewComparable(aliceID, bobID).Freeze(), prng)
		b.StartTimer()
		alice, err := rvole_mrr21.NewAlice(ctxs[aliceID], suite, prng)
		require.NoError(b, err)
		bob, err := rvole_mrr21.NewBob(ctxs[bobID], suite, prng)
		require.NoError(b, err)
		aliceR1, err := alice.Round1()
		require.NoError(b, err)
		bobR1, err := bob.Round1()
		require.NoError(b, err)
		_, err = bob.Round2(aliceR1)
		require.NoError(b, err)
		aliceR2, _, err := alice.Round2(bobR1, a)
		require.NoError(b, err)
		_, err = bob.Round3(aliceR2)
		require.NoError(b, err)
	}
}
