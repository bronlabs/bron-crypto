package rvole_softspoken_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/rvole"
	rvole_softspoken "github.com/bronlabs/bron-crypto/pkg/mpc/rvole/softspoken"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
)

// BenchmarkRVOLE measures one ℓ = 2 random VOLE over the SoftSpokenOT
// extension, both sides computed sequentially and the base OTs excluded:
// ξ = 1792 OTs, ρ = 1, one 128-bit output per row.
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
		aliceBase, bobBase := syntheticBaseOTs(b, prng)
		b.StartTimer()
		alice, err := rvole_softspoken.NewAlice(ctxs[aliceID], suite, aliceBase, prng)
		require.NoError(b, err)
		bob, err := rvole_softspoken.NewBob(ctxs[bobID], suite, bobBase, prng)
		require.NoError(b, err)
		r1, _, err := bob.Round1()
		require.NoError(b, err)
		r2, _, err := alice.Round2(r1, a)
		require.NoError(b, err)
		_, err = bob.Round3(r2)
		require.NoError(b, err)
	}
}
