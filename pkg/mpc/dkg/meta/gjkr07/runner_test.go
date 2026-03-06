package gjkr07_test

import (
	"bytes"
	"fmt"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/meta/gjkr07"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/isn"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/shamir"
	"github.com/bronlabs/bron-crypto/pkg/network"
	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
)

// ---------------------------------------------------------------------------
// Runner helpers
// ---------------------------------------------------------------------------

func makeShamirRunners(tb testing.TB, ctxs map[sharing.ID]*session.Context, group *k256.Curve, ac *accessstructures.Threshold, niCompiler compiler.Name) map[sharing.ID]network.Runner[*shamirDKGOutput] {
	tb.Helper()
	lsss, err := shamir.NewLiftableScheme(group, ac)
	require.NoError(tb, err)
	runners := make(map[sharing.ID]network.Runner[*shamirDKGOutput])
	for id, ctx := range ctxs {
		r, err := gjkr07.NewRunner(ctx, group, lsss, niCompiler, pcg.NewRandomised())
		require.NoError(tb, err)
		runners[id] = r
	}
	return runners
}

func makeISNRunners(tb testing.TB, ctxs map[sharing.ID]*session.Context, group *k256.Curve, cnf *accessstructures.CNF, niCompiler compiler.Name) map[sharing.ID]network.Runner[*isnDKGOutput] {
	tb.Helper()
	lsss, err := isn.NewFiniteLiftableScheme(group, cnf)
	require.NoError(tb, err)
	runners := make(map[sharing.ID]network.Runner[*isnDKGOutput])
	for id, ctx := range ctxs {
		r, err := gjkr07.NewRunner(ctx, group, lsss, niCompiler, pcg.NewRandomised())
		require.NoError(tb, err)
		runners[id] = r
	}
	return runners
}

// ---------------------------------------------------------------------------
// Runner tests
// ---------------------------------------------------------------------------

func TestRunnerHappyPath(t *testing.T) {
	t.Parallel()

	thresholdCases := []struct{ threshold, total uint }{
		{2, 3}, {3, 5}, {6, 6},
	}

	for _, tc := range thresholdCases {
		t.Run(fmt.Sprintf("shamir/%d-of-%d", tc.threshold, tc.total), func(t *testing.T) {
			t.Parallel()
			testShamirRunnerHappyPath(t, tc.threshold, tc.total, fiatshamir.Name)
		})
		t.Run(fmt.Sprintf("isn/%d-of-%d-cnf", tc.threshold, tc.total), func(t *testing.T) {
			t.Parallel()
			cnf := makeThresholdCNF(tc.threshold, tc.total)
			testISNRunnerHappyPath(t, cnf, fiatshamir.Name)
		})
	}

	t.Run("isn/non-threshold", func(t *testing.T) {
		t.Parallel()
		testISNRunnerHappyPath(t, defaultNonThresholdCNF, fiatshamir.Name)
	})
}

func testShamirRunnerHappyPath(t *testing.T, threshold, total uint, niCompiler compiler.Name) {
	t.Helper()

	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	shareholders := sharing.NewOrdinalShareholderSet(total)
	ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)
	ac, err := accessstructures.NewThresholdAccessStructure(threshold, shareholders)
	require.NoError(t, err)

	runners := makeShamirRunners(t, ctxs, group, ac, niCompiler)
	dkgOutputs := ntu.TestExecuteRunners(t, runners)

	t.Run("public materials are consistent", func(t *testing.T) {
		t.Parallel()
		var commonPK *k256.Point
		var commonVV *shamir.LiftedDealerFunc[*k256.Point, *k256.Scalar]
		for _, output := range dkgOutputs {
			pk := output.PublicKeyValue()
			vv := output.VerificationVector()
			if commonPK == nil {
				commonPK = pk
				commonVV = vv
			} else {
				require.True(t, commonPK.Equal(pk))
				require.True(t, sharing.DealerFuncsAreEqual(commonVV, vv))
			}
		}
	})

	t.Run("secret shares are consistent", func(t *testing.T) {
		t.Parallel()
		var publicKeyValue *k256.Point
		var referenceVV *shamir.LiftedDealerFunc[*k256.Point, *k256.Scalar]
		shares := make([]*shamir.Share[*k256.Scalar], 0, len(dkgOutputs))
		for _, output := range dkgOutputs {
			if publicKeyValue == nil {
				publicKeyValue = output.PublicKeyValue()
				referenceVV = output.VerificationVector()
			}
			shares = append(shares, output.Share())
		}

		feldmanScheme := newShamirFeldmanScheme(t, group, ac)
		for sharesSubset := range sliceutils.KCoveringCombinations(shares, threshold) {
			secret, err := feldmanScheme.ReconstructAndVerify(referenceVV, sharesSubset...)
			require.NoError(t, err)
			reconstructedPK := group.ScalarBaseOp(secret.Value())
			require.True(t, reconstructedPK.Equal(publicKeyValue))
		}
	})

	t.Run("transcripts are consistent", func(t *testing.T) {
		t.Parallel()
		ids := make([]sharing.ID, 0, shareholders.Size())
		for id := range shareholders.Iter() {
			ids = append(ids, id)
		}
		slices.Sort(ids)

		var tapeSamples [][]byte
		for _, id := range ids {
			tapeSample, err := ctxs[id].Transcript().ExtractBytes("test", 32)
			require.NoError(t, err)
			tapeSamples = append(tapeSamples, tapeSample)
		}
		for i := 1; i < len(tapeSamples); i++ {
			require.True(t, bytes.Equal(tapeSamples[i-1], tapeSamples[i]))
		}
	})
}

func testISNRunnerHappyPath(t *testing.T, cnf *accessstructures.CNF, niCompiler compiler.Name) {
	t.Helper()

	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	ctxs := session_testutils.MakeRandomContexts(t, cnf.Shareholders(), prng)

	runners := makeISNRunners(t, ctxs, group, cnf, niCompiler)
	dkgOutputs := ntu.TestExecuteRunners(t, runners)

	t.Run("public materials are consistent", func(t *testing.T) {
		t.Parallel()
		var commonPK *k256.Point
		first := true
		var commonVV isn.LiftedDealerFunc[*k256.Point, *k256.Scalar]
		for _, output := range dkgOutputs {
			pk := output.PublicKeyValue()
			vv := output.VerificationVector()
			if first {
				commonPK = pk
				commonVV = vv
				first = false
			} else {
				require.True(t, commonPK.Equal(pk))
				require.True(t, sharing.DealerFuncsAreEqual(commonVV, vv))
			}
		}
	})

	t.Run("secret shares are consistent", func(t *testing.T) {
		t.Parallel()
		var publicKeyValue *k256.Point
		var referenceVV isn.LiftedDealerFunc[*k256.Point, *k256.Scalar]
		sharesByID := make(map[sharing.ID]*isn.Share[*k256.Scalar])
		first := true
		for _, output := range dkgOutputs {
			if first {
				publicKeyValue = output.PublicKeyValue()
				referenceVV = output.VerificationVector()
				first = false
			}
			sharesByID[output.Share().ID()] = output.Share()
		}

		feldmanScheme := newISNFeldmanScheme(t, group, cnf)
		for _, combo := range qualifiedSubsetsForCNF(cnf) {
			subset := make([]*isn.Share[*k256.Scalar], 0, len(combo))
			for _, id := range combo {
				subset = append(subset, sharesByID[id])
			}
			secret, err := feldmanScheme.ReconstructAndVerify(referenceVV, subset...)
			require.NoError(t, err)
			reconstructedPK := group.ScalarBaseOp(secret.Value())
			require.True(t, reconstructedPK.Equal(publicKeyValue))
		}
	})

	t.Run("transcripts are consistent", func(t *testing.T) {
		t.Parallel()
		ids := make([]sharing.ID, 0, cnf.Shareholders().Size())
		for id := range cnf.Shareholders().Iter() {
			ids = append(ids, id)
		}
		slices.Sort(ids)

		var tapeSamples [][]byte
		for _, id := range ids {
			tapeSample, err := ctxs[id].Transcript().ExtractBytes("test", 32)
			require.NoError(t, err)
			tapeSamples = append(tapeSamples, tapeSample)
		}
		for i := 1; i < len(tapeSamples); i++ {
			require.True(t, bytes.Equal(tapeSamples[i-1], tapeSamples[i]))
		}
	})
}
