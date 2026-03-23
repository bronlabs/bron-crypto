package feldman_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/boolexpr"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/cnf"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/hierarchical"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func shareholders(ids ...sharing.ID) ds.Set[sharing.ID] {
	return hashset.NewComparable(ids...).Freeze()
}

func formatIDs(ids []sharing.ID) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("%d", id)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func newFeldmanScheme[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]](
	tb testing.TB,
	group algebra.PrimeGroup[E, FE],
	ac accessstructures.Linear,
) *feldman.Scheme[E, FE] {
	tb.Helper()
	scheme, err := feldman.NewScheme(group, ac)
	require.NoError(tb, err)
	return scheme
}

func dealFeldman[E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE]](
	tb testing.TB,
	scheme *feldman.Scheme[E, FE],
	secret *kw.Secret[FE],
) (*feldman.DealerOutput[E, FE], map[sharing.ID]*kw.Share[FE]) {
	tb.Helper()
	out, err := scheme.Deal(secret, pcg.NewRandomised())
	require.NoError(tb, err)
	m := make(map[sharing.ID]*kw.Share[FE])
	for id, sh := range out.Shares().Iter() {
		m[id] = sh
	}
	return out, m
}

func pickShares[FE algebra.PrimeFieldElement[FE]](m map[sharing.ID]*kw.Share[FE], ids ...sharing.ID) []*kw.Share[FE] {
	out := make([]*kw.Share[FE], len(ids))
	for i, id := range ids {
		out[i] = m[id]
	}
	return out
}

func newUnanimity(t *testing.T, ids ...sharing.ID) *unanimity.Unanimity {
	t.Helper()
	q, err := unanimity.NewUnanimityAccessStructure(shareholders(ids...))
	require.NoError(t, err)
	return q
}

// ---------------------------------------------------------------------------
// access structure fixtures
// ---------------------------------------------------------------------------

type acFixture struct {
	name         string
	ac           accessstructures.Linear
	qualified    [][]sharing.ID
	unqualified  [][]sharing.ID
	shareholders []sharing.ID
}

func thresholdFixture(t *testing.T) acFixture {
	t.Helper()
	ac, err := threshold.NewThresholdAccessStructure(2, shareholders(1, 2, 3))
	require.NoError(t, err)
	return acFixture{
		name: "threshold(2,3)",
		ac:   ac,
		qualified: [][]sharing.ID{
			{1, 2},
			{1, 3},
			{2, 3},
			{1, 2, 3},
		},
		unqualified: [][]sharing.ID{
			{1},
			{2},
			{3},
		},
		shareholders: []sharing.ID{1, 2, 3},
	}
}

func unanimityFixture(t *testing.T) acFixture {
	t.Helper()
	ac, err := unanimity.NewUnanimityAccessStructure(shareholders(1, 2, 3))
	require.NoError(t, err)
	return acFixture{
		name: "unanimity(3)",
		ac:   ac,
		qualified: [][]sharing.ID{
			{1, 2, 3},
		},
		unqualified: [][]sharing.ID{
			{1},
			{2},
			{1, 2},
			{1, 3},
			{2, 3},
		},
		shareholders: []sharing.ID{1, 2, 3},
	}
}

func cnfFixture(t *testing.T) acFixture {
	t.Helper()
	// Maximal unqualified: {1,2} and {3,4}
	ac, err := cnf.NewCNFAccessStructure(
		shareholders(1, 2),
		shareholders(3, 4),
	)
	require.NoError(t, err)
	return acFixture{
		name: "cnf({1,2},{3,4})",
		ac:   ac,
		qualified: [][]sharing.ID{
			{1, 3},
			{1, 4},
			{2, 3},
			{2, 4},
			{1, 2, 3},
			{1, 3, 4},
			{1, 2, 3, 4},
		},
		unqualified: [][]sharing.ID{
			{1},
			{2},
			{3},
			{4},
			{1, 2},
			{3, 4},
		},
		shareholders: []sharing.ID{1, 2, 3, 4},
	}
}

func cnfThreeClauseFixture(t *testing.T) acFixture {
	t.Helper()
	// Maximal unqualified: {1,2}, {3,4}, {5}
	ac, err := cnf.NewCNFAccessStructure(
		shareholders(1, 2),
		shareholders(3, 4),
		shareholders(5),
	)
	require.NoError(t, err)
	return acFixture{
		name: "cnf({1,2},{3,4},{5})",
		ac:   ac,
		qualified: [][]sharing.ID{
			{1, 3},
			{3, 5},
			{1, 3, 4},
			{1, 2, 3, 4, 5},
		},
		unqualified: [][]sharing.ID{
			{1, 2},
			{3, 4},
			{5},
		},
		shareholders: []sharing.ID{1, 2, 3, 4, 5},
	}
}

func largeThresholdFixture(t *testing.T) acFixture {
	t.Helper()
	ids := make([]sharing.ID, 7)
	for i := range ids {
		ids[i] = sharing.ID(i + 1)
	}
	ac, err := threshold.NewThresholdAccessStructure(4, shareholders(ids...))
	require.NoError(t, err)
	return acFixture{
		name: "threshold(4,7)",
		ac:   ac,
		qualified: [][]sharing.ID{
			{1, 2, 3, 4},
			{2, 4, 5, 7},
			{1, 2, 3, 4, 5, 6, 7},
		},
		unqualified: [][]sharing.ID{
			{1, 2, 3},
			{5, 6, 7},
			{1},
		},
		shareholders: ids,
	}
}

func hierarchicalTwoLevelFixture(t *testing.T) acFixture {
	t.Helper()
	ac, err := hierarchical.NewHierarchicalConjunctiveThresholdAccessStructure(
		hierarchical.WithLevel(2, 1, 2, 3),
		hierarchical.WithLevel(4, 4, 5, 6),
	)
	require.NoError(t, err)
	return acFixture{
		name: "hierarchical(2,4)",
		ac:   ac,
		qualified: [][]sharing.ID{
			{1, 2, 4, 5},
			{1, 2, 3, 4},
			{2, 3, 5, 6},
			{1, 2, 3, 4, 5, 6},
		},
		unqualified: [][]sharing.ID{
			{1, 4, 5},
			{4, 5, 6},
			{1, 2, 3},
			{3, 4, 5, 6},
		},
		shareholders: []sharing.ID{1, 2, 3, 4, 5, 6},
	}
}

func hierarchicalThreeLevelFixture(t *testing.T) acFixture {
	t.Helper()
	ac, err := hierarchical.NewHierarchicalConjunctiveThresholdAccessStructure(
		hierarchical.WithLevel(1, 1, 2),
		hierarchical.WithLevel(2, 3, 4),
		hierarchical.WithLevel(4, 5, 6),
	)
	require.NoError(t, err)
	return acFixture{
		name: "hierarchical(1,2,4)",
		ac:   ac,
		qualified: [][]sharing.ID{
			{1, 3, 5, 6},
			{2, 4, 5, 6},
			{1, 2, 3, 4},
			{1, 2, 3, 4, 5, 6},
		},
		unqualified: [][]sharing.ID{
			{3, 5, 6},
			{1, 5, 6},
			{5, 6},
			{1, 3, 5},
		},
		shareholders: []sharing.ID{1, 2, 3, 4, 5, 6},
	}
}

func boolexprThreeBranchFixture(t *testing.T) acFixture {
	t.Helper()
	// 2-of-3 threshold gate over three 2-of-3 threshold gates
	ac, err := boolexpr.NewThresholdGateAccessStructure(
		boolexpr.Threshold(2,
			boolexpr.Threshold(2,
				boolexpr.ID(1),
				boolexpr.ID(2),
				boolexpr.ID(3),
			),
			boolexpr.Threshold(2,
				boolexpr.ID(4),
				boolexpr.ID(5),
				boolexpr.ID(6),
			),
			boolexpr.Threshold(2,
				boolexpr.ID(7),
				boolexpr.ID(8),
				boolexpr.ID(9),
			),
		),
	)
	require.NoError(t, err)
	return acFixture{
		name: "boolexpr(2-of-3 branches)",
		ac:   ac,
		qualified: [][]sharing.ID{
			{1, 2, 4, 5},
			{1, 3, 7, 8},
			{4, 5, 7, 9},
			{1, 2, 4, 5, 7, 8},
		},
		unqualified: [][]sharing.ID{
			{1},
			{1, 2},
			{1, 2, 3, 4},
			{4, 7, 8},
		},
		shareholders: []sharing.ID{1, 2, 3, 4, 5, 6, 7, 8, 9},
	}
}

func boolexprNestedFixture(t *testing.T) acFixture {
	t.Helper()
	// Deeper nesting: 2-of-3 top gate, with an AND gate containing an
	// embedded 3-of-4 threshold.
	ac, err := boolexpr.NewThresholdGateAccessStructure(
		boolexpr.Threshold(2,
			boolexpr.Threshold(2,
				boolexpr.ID(1),
				boolexpr.ID(2),
				boolexpr.ID(3),
			),
			boolexpr.Threshold(2,
				boolexpr.ID(4),
				boolexpr.ID(5),
				boolexpr.ID(6),
			),
			boolexpr.Threshold(2,
				boolexpr.ID(7),
				boolexpr.ID(8),
				boolexpr.Threshold(3,
					boolexpr.ID(9),
					boolexpr.ID(10),
					boolexpr.ID(11),
					boolexpr.ID(12),
				),
			),
		),
	)
	require.NoError(t, err)
	return acFixture{
		name: "boolexpr(nested-example-c)",
		ac:   ac,
		qualified: [][]sharing.ID{
			{1, 2, 4, 5},
			{1, 2, 7, 8},
			{4, 5, 7, 9, 10, 11},
			{1, 2, 8, 9, 10, 11},
		},
		unqualified: [][]sharing.ID{
			{1, 2, 3, 4},
			{7, 9, 10, 11},
			{1, 4, 7, 8},
			{8, 9, 10},
		},
		shareholders: []sharing.ID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
	}
}

func boolexprAndOrFixture(t *testing.T) acFixture {
	t.Helper()
	// (1 AND 2) OR (3 AND 4)   (using threshold gates: AND=t/t, OR=1/t)
	ac, err := boolexpr.NewThresholdGateAccessStructure(
		boolexpr.Or(
			boolexpr.And(boolexpr.ID(1), boolexpr.ID(2)),
			boolexpr.And(boolexpr.ID(3), boolexpr.ID(4)),
		),
	)
	require.NoError(t, err)
	return acFixture{
		name: "boolexpr((1∧2)∨(3∧4))",
		ac:   ac,
		qualified: [][]sharing.ID{
			{1, 2},
			{3, 4},
			{1, 2, 3},
			{1, 2, 3, 4},
		},
		unqualified: [][]sharing.ID{
			{1},
			{3},
			{1, 3},
			{2, 4},
			{1, 4},
		},
		shareholders: []sharing.ID{1, 2, 3, 4},
	}
}

func allFixtures(t *testing.T) []acFixture {
	t.Helper()
	return []acFixture{
		thresholdFixture(t),
		unanimityFixture(t),
		cnfFixture(t),
		cnfThreeClauseFixture(t),
		largeThresholdFixture(t),
		hierarchicalTwoLevelFixture(t),
		hierarchicalThreeLevelFixture(t),
		boolexprThreeBranchFixture(t),
		boolexprNestedFixture(t),
		boolexprAndOrFixture(t),
	}
}

// ---------------------------------------------------------------------------
// NewScheme – construction
// ---------------------------------------------------------------------------

func TestNewScheme(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()

	t.Run("valid with each access structure", func(t *testing.T) {
		t.Parallel()
		for _, fx := range allFixtures(t) {
			t.Run(fx.name, func(t *testing.T) {
				t.Parallel()
				scheme, err := feldman.NewScheme(curve, fx.ac)
				require.NoError(t, err)
				require.NotNil(t, scheme)
				require.Equal(t, feldman.Name, scheme.Name())
				require.Equal(t, len(fx.shareholders), scheme.AccessStructure().Shareholders().Size())
			})
		}
	})

	t.Run("nil group", func(t *testing.T) {
		t.Parallel()
		ac, err := threshold.NewThresholdAccessStructure(2, shareholders(1, 2, 3))
		require.NoError(t, err)
		_, err = feldman.NewScheme[*k256.Point, *k256.Scalar](nil, ac)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrIsNil)
	})

	t.Run("nil access structure", func(t *testing.T) {
		t.Parallel()
		_, err := feldman.NewScheme[*k256.Point, *k256.Scalar](curve, nil)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrIsNil)
	})
}

// ---------------------------------------------------------------------------
// Deal + Reconstruct – qualified sets recover the secret
// ---------------------------------------------------------------------------

func TestDealAndReconstruct_QualifiedSets(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newFeldmanScheme(t, curve, fx.ac)
			secret := kw.NewSecret(field.FromUint64(42))
			_, shares := dealFeldman(t, scheme, secret)

			for _, qset := range fx.qualified {
				t.Run(formatIDs(qset), func(t *testing.T) {
					t.Parallel()
					reconstructed, err := scheme.Reconstruct(pickShares(shares, qset...)...)
					require.NoError(t, err)
					require.True(t, secret.Equal(reconstructed),
						"qualified set %v must reconstruct the secret", qset)
				})
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Reconstruct – unqualified sets are rejected
// ---------------------------------------------------------------------------

func TestReconstruct_UnqualifiedSets(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newFeldmanScheme(t, curve, fx.ac)
			secret := kw.NewSecret(field.FromUint64(654321))
			_, shares := dealFeldman(t, scheme, secret)

			for _, uset := range fx.unqualified {
				t.Run(formatIDs(uset), func(t *testing.T) {
					t.Parallel()
					_, err := scheme.Reconstruct(pickShares(shares, uset...)...)
					require.Error(t, err)
				})
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Verification: every share passes Verify against the verification vector
// ---------------------------------------------------------------------------

func TestVerify_HonestShares(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newFeldmanScheme(t, curve, fx.ac)
			secret := kw.NewSecret(field.FromUint64(9999))
			out, _ := dealFeldman(t, scheme, secret)
			ref := out.VerificationMaterial()

			for _, id := range fx.shareholders {
				t.Run(fmt.Sprintf("id=%d", id), func(t *testing.T) {
					t.Parallel()
					sh, ok := out.Shares().Get(id)
					require.True(t, ok)
					err := scheme.Verify(sh, ref)
					require.NoError(t, err, "honest share for ID %d must verify", id)
				})
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Verification: tampered share is detected
// ---------------------------------------------------------------------------

func TestVerify_TamperedShare(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newFeldmanScheme(t, curve, fx.ac)
			secret := kw.NewSecret(field.FromUint64(1234))
			out, _ := dealFeldman(t, scheme, secret)
			ref := out.VerificationMaterial()

			// Pick the first shareholder and tamper with their share
			id := fx.shareholders[0]
			honest, ok := out.Shares().Get(id)
			require.True(t, ok)

			// Create a tampered share by adding one to each component
			tamperedValues := make([]FE, len(honest.Value()))
			for i, v := range honest.Value() {
				tamperedValues[i] = v.Add(field.One())
			}
			tampered, err := kw.NewShare(id, tamperedValues...)
			require.NoError(t, err)

			err = scheme.Verify(tampered, ref)
			require.Error(t, err)
			require.ErrorIs(t, err, sharing.ErrVerification)
		})
	}
}

// ---------------------------------------------------------------------------
// Verification: wrong verification vector is detected
// ---------------------------------------------------------------------------

func TestVerify_WrongVerificationVector(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newFeldmanScheme(t, curve, fx.ac)
			s1 := kw.NewSecret(field.FromUint64(100))
			s2 := kw.NewSecret(field.FromUint64(200))

			out1, _ := dealFeldman(t, scheme, s1)
			out2, _ := dealFeldman(t, scheme, s2)

			// Verify shares from dealing 1 against the verification vector from dealing 2
			id := fx.shareholders[0]
			sh, ok := out1.Shares().Get(id)
			require.True(t, ok)
			err := scheme.Verify(sh, out2.VerificationMaterial())
			require.Error(t, err, "share from one dealing must not verify against a different verification vector")
			require.ErrorIs(t, err, sharing.ErrVerification)
		})
	}
}

// ---------------------------------------------------------------------------
// ReconstructAndVerify – happy path
// ---------------------------------------------------------------------------

func TestReconstructAndVerify_QualifiedSets(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newFeldmanScheme(t, curve, fx.ac)
			secret := kw.NewSecret(field.FromUint64(77777))
			out, shares := dealFeldman(t, scheme, secret)
			ref := out.VerificationMaterial()

			for _, qset := range fx.qualified {
				t.Run(formatIDs(qset), func(t *testing.T) {
					t.Parallel()
					reconstructed, err := scheme.ReconstructAndVerify(ref, pickShares(shares, qset...)...)
					require.NoError(t, err)
					require.True(t, secret.Equal(reconstructed))
				})
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ReconstructAndVerify – rejects tampered share
// ---------------------------------------------------------------------------

func TestReconstructAndVerify_RejectsTamperedShare(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newFeldmanScheme(t, curve, fx.ac)
	secret := kw.NewSecret(field.FromUint64(42))
	out, shares := dealFeldman(t, scheme, secret)
	ref := out.VerificationMaterial()

	// Tamper with one share in a qualified set
	qset := fx.qualified[0]
	pickedShares := pickShares(shares, qset...)
	honest := pickedShares[0]
	tamperedValues := make([]FE, len(honest.Value()))
	for i, v := range honest.Value() {
		tamperedValues[i] = v.Add(field.One())
	}
	tampered, err := kw.NewShare(honest.ID(), tamperedValues...)
	require.NoError(t, err)
	pickedShares[0] = tampered

	_, err = scheme.ReconstructAndVerify(ref, pickedShares...)
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrVerification)
}

// ---------------------------------------------------------------------------
// Verify nil share
// ---------------------------------------------------------------------------

func TestVerify_NilShare(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newFeldmanScheme(t, curve, fx.ac)

	out, _ := dealFeldman(t, scheme, kw.NewSecret(field.One()))
	err := scheme.Verify(nil, out.VerificationMaterial())
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrIsNil)
}

// ---------------------------------------------------------------------------
// DealRandom: returns valid output and reconstructs
// ---------------------------------------------------------------------------

func TestDealRandom(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newFeldmanScheme(t, curve, fx.ac)

			out, secret, err := scheme.DealRandom(pcg.NewRandomised())
			require.NoError(t, err)
			require.NotNil(t, out)
			require.NotNil(t, secret)
			require.Equal(t, len(fx.shareholders), out.Shares().Size())

			// Verify every share
			ref := out.VerificationMaterial()
			for _, sh := range out.Shares().Values() {
				require.NoError(t, scheme.Verify(sh, ref))
			}

			// Reconstruct using a qualified set
			m := make(map[sharing.ID]*kw.Share[*k256.Scalar])
			for id, sh := range out.Shares().Iter() {
				m[id] = sh
			}
			reconstructed, err := scheme.Reconstruct(pickShares(m, fx.qualified[0]...)...)
			require.NoError(t, err)
			require.True(t, secret.Equal(reconstructed))
		})
	}
}

// ---------------------------------------------------------------------------
// DealRandom produces distinct secrets on consecutive calls
// ---------------------------------------------------------------------------

func TestDealRandom_Freshness(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	fx := thresholdFixture(t)
	scheme := newFeldmanScheme(t, curve, fx.ac)
	prng := pcg.NewRandomised()

	_, s1, err := scheme.DealRandom(prng)
	require.NoError(t, err)
	_, s2, err := scheme.DealRandom(prng)
	require.NoError(t, err)
	require.False(t, s1.Equal(s2), "consecutive DealRandom must produce different secrets")
}

// ---------------------------------------------------------------------------
// DealAndRevealDealerFunc: dealer func secret matches the dealt secret
// ---------------------------------------------------------------------------

func TestDealAndRevealDealerFunc(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newFeldmanScheme(t, curve, fx.ac)
			secret := kw.NewSecret(field.FromUint64(55))

			out, df, err := scheme.DealAndRevealDealerFunc(secret, pcg.NewRandomised())
			require.NoError(t, err)
			require.NotNil(t, out)
			require.NotNil(t, df)
			require.True(t, secret.Equal(df.Secret()),
				"dealer func secret must match the dealt secret")
		})
	}
}

// ---------------------------------------------------------------------------
// Verification vector correctness: V = Lift(randomColumn, G)
// ---------------------------------------------------------------------------

func TestVerificationVector_IsLiftOfRandomColumn(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newFeldmanScheme(t, curve, fx.ac)
			secret := kw.NewSecret(field.FromUint64(42))

			out, df, err := scheme.DealAndRevealDealerFunc(secret, pcg.NewRandomised())
			require.NoError(t, err)

			expectedMat, err := mat.Lift(df.RandomColumn(), curve.Generator())
			require.NoError(t, err)
			expectedVV, err := feldman.NewVerificationVector(expectedMat, df.MSP())
			require.NoError(t, err)
			require.True(t, out.VerificationMaterial().Equal(expectedVV),
				"verification vector must equal Lift(randomColumn, G)")
		})
	}
}

// ---------------------------------------------------------------------------
// Feldman core check: Verify(share, V) ⟺ [share]G == M_i * V
// For each shareholder, lifting the scalar share to the group must equal
// the result of the left module action of the shareholder's MSP rows on V.
// ---------------------------------------------------------------------------

func TestFeldmanCoreEquation(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	gen := curve.Generator()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newFeldmanScheme(t, curve, fx.ac)
			secret := kw.NewSecret(field.FromUint64(31337))

			out, df, err := scheme.DealAndRevealDealerFunc(secret, pcg.NewRandomised())
			require.NoError(t, err)
			vv := out.VerificationMaterial()

			// Construct the verifier's LiftedDealerFunc from the public V and the MSP
			ldf, err := feldman.NewLiftedDealerFunc(vv, df.MSP())
			require.NoError(t, err)

			for _, id := range fx.shareholders {
				// Public: expected lifted share from V
				expectedLifted, err := ldf.ShareOf(id)
				require.NoError(t, err)

				// Private: manually lift the scalar share
				scalarShare, ok := out.Shares().Get(id)
				require.True(t, ok)
				manuallyLifted, err := feldman.LiftShare(scalarShare, gen)
				require.NoError(t, err)

				require.True(t, expectedLifted.Equal(manuallyLifted),
					"Feldman equation failed for ID %d: M_i * V ≠ [λ_i]G", id)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Round-trip with random secrets
// ---------------------------------------------------------------------------

func TestRoundTrip_RandomSecrets(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	prng := pcg.NewRandomised()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newFeldmanScheme(t, curve, fx.ac)

			for range 5 {
				val, err := field.Random(prng)
				require.NoError(t, err)
				secret := kw.NewSecret(val)
				out, shares := dealFeldman(t, scheme, secret)
				ref := out.VerificationMaterial()

				for _, qset := range fx.qualified {
					reconstructed, err := scheme.ReconstructAndVerify(ref, pickShares(shares, qset...)...)
					require.NoError(t, err)
					require.True(t, secret.Equal(reconstructed))
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Zero secret: share + verify + reconstruct
// ---------------------------------------------------------------------------

func TestZeroSecret(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newFeldmanScheme(t, curve, fx.ac)
			secret := kw.NewSecret(field.Zero())
			out, shares := dealFeldman(t, scheme, secret)
			ref := out.VerificationMaterial()

			// Verify every share
			for _, sh := range out.Shares().Values() {
				require.NoError(t, scheme.Verify(sh, ref))
			}

			// Reconstruct
			for _, qset := range fx.qualified {
				reconstructed, err := scheme.Reconstruct(pickShares(shares, qset...)...)
				require.NoError(t, err)
				require.True(t, secret.Equal(reconstructed),
					"zero secret must reconstruct to zero")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Homomorphic addition: shares of a + shares of b reconstruct to a+b
// ---------------------------------------------------------------------------

func TestHomomorphicAddition(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newFeldmanScheme(t, curve, fx.ac)

			s1 := kw.NewSecret(field.FromUint64(500))
			s2 := kw.NewSecret(field.FromUint64(300))

			_, shares1 := dealFeldman(t, scheme, s1)
			_, shares2 := dealFeldman(t, scheme, s2)

			combined := make(map[sharing.ID]*kw.Share[*k256.Scalar], len(shares1))
			for id, sh1 := range shares1 {
				combined[id] = sh1.Add(shares2[id])
			}

			for _, qset := range fx.qualified {
				reconstructed, err := scheme.Reconstruct(pickShares(combined, qset...)...)
				require.NoError(t, err)
				expected := s1.Value().Add(s2.Value())
				require.True(t, expected.Equal(reconstructed.Value()),
					"share addition should reconstruct to secret addition for set %v", qset)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Homomorphic scalar multiplication
// ---------------------------------------------------------------------------

func TestHomomorphicScalarMul(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newFeldmanScheme(t, curve, fx.ac)

			s := kw.NewSecret(field.FromUint64(42))
			scalar := field.FromUint64(7)

			_, shares := dealFeldman(t, scheme, s)

			scaled := make(map[sharing.ID]*kw.Share[*k256.Scalar], len(shares))
			for id, sh := range shares {
				scaled[id] = sh.ScalarMul(scalar)
			}

			for _, qset := range fx.qualified {
				reconstructed, err := scheme.Reconstruct(pickShares(scaled, qset...)...)
				require.NoError(t, err)
				expected := s.Value().Mul(scalar)
				require.True(t, expected.Equal(reconstructed.Value()),
					"scalar multiplication should be homomorphic for set %v", qset)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Privacy: individual shares from two different secrets are distinct
// (basic smoke-test for randomness independence)
// ---------------------------------------------------------------------------

func TestPrivacy_SingleShareRevealsNothing(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newFeldmanScheme(t, curve, fx.ac)

			s1 := kw.NewSecret(field.FromUint64(100))
			s2 := kw.NewSecret(field.FromUint64(200))

			_, shares1 := dealFeldman(t, scheme, s1)
			_, shares2 := dealFeldman(t, scheme, s2)

			for _, id := range fx.shareholders {
				require.False(t, shares1[id].Equal(shares2[id]),
					"shares for ID %d should be randomised independently", id)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Determinism: same PRNG seed → identical outputs
// ---------------------------------------------------------------------------

func TestDeterminism(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newFeldmanScheme(t, curve, fx.ac)
	secret := kw.NewSecret(field.FromUint64(42))

	out1, err := scheme.Deal(secret, pcg.New(11111, 22222))
	require.NoError(t, err)
	out2, err := scheme.Deal(secret, pcg.New(11111, 22222))
	require.NoError(t, err)

	for _, id := range fx.shareholders {
		sh1, ok := out1.Shares().Get(id)
		require.True(t, ok)
		sh2, ok := out2.Shares().Get(id)
		require.True(t, ok)
		require.True(t, sh1.Equal(sh2), "same seed must produce same shares for ID %d", id)
	}

	require.True(t, out1.VerificationMaterial().Equal(out2.VerificationMaterial()),
		"same seed must produce same verification vector")
}

// ---------------------------------------------------------------------------
// Verification vector for different dealings are distinct
// ---------------------------------------------------------------------------

func TestVerificationVector_DistinctPerDealing(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newFeldmanScheme(t, curve, fx.ac)

	out1, _ := dealFeldman(t, scheme, kw.NewSecret(field.FromUint64(1)))
	out2, _ := dealFeldman(t, scheme, kw.NewSecret(field.FromUint64(1)))

	// Different randomness ⟹ different verification vectors
	require.False(t, out1.VerificationMaterial().Equal(out2.VerificationMaterial()),
		"distinct dealings should produce distinct verification vectors")
}

// ---------------------------------------------------------------------------
// NewVerificationVector – construction
// ---------------------------------------------------------------------------

func TestNewVerificationVector_Valid(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newFeldmanScheme(t, curve, fx.ac)

	_, df, err := scheme.DealAndRevealDealerFunc(kw.NewSecret(field.One()), pcg.NewRandomised())
	require.NoError(t, err)

	lifted, err := mat.Lift(df.RandomColumn(), curve.Generator())
	require.NoError(t, err)

	vv, err := feldman.NewVerificationVector(lifted, df.MSP())
	require.NoError(t, err)
	require.NotNil(t, vv)
	require.True(t, lifted.Equal(vv.Value()))
}

func TestNewVerificationVector_NilValue(t *testing.T) {
	t.Parallel()

	_, err := feldman.NewVerificationVector[*k256.Point](nil, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrIsNil)
}

func TestNewVerificationVector_NotColumnVector(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	curve := k256.NewCurve()

	// Create a row vector (1 x 2) instead of column
	rowMod, err := mat.NewMatrixModule(1, 2, field)
	require.NoError(t, err)
	row, err := rowMod.NewRowMajor(field.One(), field.Zero())
	require.NoError(t, err)
	rowLifted, err := mat.Lift(row, curve.Generator())
	require.NoError(t, err)

	_, err = feldman.NewVerificationVector(rowLifted, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrValue)
}

func TestNewVerificationVector_DimensionMismatch(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newFeldmanScheme(t, curve, fx.ac)

	_, df, err := scheme.DealAndRevealDealerFunc(kw.NewSecret(field.One()), pcg.NewRandomised())
	require.NoError(t, err)

	// Build a column vector with wrong number of rows (D + 1)
	d, _ := df.RandomColumn().Dimensions()
	wrongMod, err := mat.NewMatrixModule(uint(d+1), 1, field)
	require.NoError(t, err)
	entries := make([]*k256.Scalar, d+1)
	for i := range d + 1 {
		entries[i] = field.FromUint64(uint64(i + 1))
	}
	wrongCol, err := wrongMod.NewRowMajor(entries...)
	require.NoError(t, err)
	wrongLifted, err := mat.Lift(wrongCol, curve.Generator())
	require.NoError(t, err)

	_, err = feldman.NewVerificationVector(wrongLifted, df.MSP())
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrValue)
}

func TestNewVerificationVector_NilMSPSkipsDimensionCheck(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()

	// Any column vector should be accepted when MSP is nil
	colMod, err := mat.NewMatrixModule(3, 1, field)
	require.NoError(t, err)
	col, err := colMod.NewRowMajor(field.One(), field.One(), field.One())
	require.NoError(t, err)
	lifted, err := mat.Lift(col, curve.Generator())
	require.NoError(t, err)

	vv, err := feldman.NewVerificationVector(lifted, nil)
	require.NoError(t, err)
	require.NotNil(t, vv)
}

// ---------------------------------------------------------------------------
// VerificationVector – Equal, HashCode
// ---------------------------------------------------------------------------

func TestVerificationVector_Equal(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newFeldmanScheme(t, curve, fx.ac)
	secret := kw.NewSecret(field.FromUint64(42))

	out1, _ := dealFeldman(t, scheme, secret)
	out2, _ := dealFeldman(t, scheme, secret)

	vv1 := out1.VerificationMaterial()

	t.Run("equal to self", func(t *testing.T) {
		t.Parallel()
		require.True(t, vv1.Equal(vv1))
	})

	t.Run("not equal to different", func(t *testing.T) {
		t.Parallel()
		vv2 := out2.VerificationMaterial()
		require.False(t, vv1.Equal(vv2))
	})

	t.Run("not equal to nil", func(t *testing.T) {
		t.Parallel()
		require.False(t, vv1.Equal(nil))
	})

	t.Run("nil equals nil", func(t *testing.T) {
		t.Parallel()
		var a, b *feldman.VerificationVector[*k256.Point, *k256.Scalar]
		require.True(t, a.Equal(b))
	})
}

func TestVerificationVector_HashCode(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newFeldmanScheme(t, curve, fx.ac)
	secret := kw.NewSecret(field.FromUint64(42))

	out1, _ := dealFeldman(t, scheme, secret)
	out2, _ := dealFeldman(t, scheme, secret)

	require.NotEqual(t, out1.VerificationMaterial().HashCode(), out2.VerificationMaterial().HashCode())
}

// ---------------------------------------------------------------------------
// VerificationVector – Op (component-wise group addition)
// ---------------------------------------------------------------------------

func TestVerificationVector_Op_HomomorphicProperty(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	gen := curve.Generator()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newFeldmanScheme(t, curve, fx.ac)

			s1 := kw.NewSecret(field.FromUint64(100))
			s2 := kw.NewSecret(field.FromUint64(200))

			out1, df1, err := scheme.DealAndRevealDealerFunc(s1, pcg.NewRandomised())
			require.NoError(t, err)
			out2, df2, err := scheme.DealAndRevealDealerFunc(s2, pcg.NewRandomised())
			require.NoError(t, err)

			// Op the two verification vectors
			combined := out1.VerificationMaterial().Op(out2.VerificationMaterial())

			// The first entry of the combined VV should equal
			// [s1]G + [s2]G = [s1+s2]G
			expectedSecret := gen.ScalarOp(s1.Value().Add(s2.Value()))
			combinedFirst, err := combined.Value().Get(0, 0)
			require.NoError(t, err)
			require.True(t, expectedSecret.Equal(combinedFirst),
				"first entry of Op'd VV must equal [s1+s2]G")

			// Each entry should equal the component-wise sum of the
			// individual verification vectors' entries.
			r1 := df1.RandomColumn()
			r2 := df2.RandomColumn()
			d, _ := r1.Dimensions()
			for i := range d {
				v1, err := out1.VerificationMaterial().Value().Get(i, 0)
				require.NoError(t, err)
				v2, err := out2.VerificationMaterial().Value().Get(i, 0)
				require.NoError(t, err)
				vc, err := combined.Value().Get(i, 0)
				require.NoError(t, err)

				// Manual: [r1_i]G + [r2_i]G
				r1i, err := r1.Get(i, 0)
				require.NoError(t, err)
				r2i, err := r2.Get(i, 0)
				require.NoError(t, err)
				expected := gen.ScalarOp(r1i.Add(r2i))
				require.True(t, expected.Equal(vc),
					"combined VV[%d] must equal [r1_%d + r2_%d]G", i, i, i)
				require.True(t, v1.Op(v2).Equal(vc),
					"combined VV[%d] must equal VV1[%d] + VV2[%d]", i, i, i)
			}
		})
	}
}

func TestVerificationVector_Op_VerifyCombinedShares(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newFeldmanScheme(t, curve, fx.ac)

			s1 := kw.NewSecret(field.FromUint64(500))
			s2 := kw.NewSecret(field.FromUint64(300))

			out1, shares1 := dealFeldman(t, scheme, s1)
			out2, shares2 := dealFeldman(t, scheme, s2)

			combinedVV := out1.VerificationMaterial().Op(out2.VerificationMaterial())

			// Adding shares component-wise should verify against the Op'd VV
			for _, id := range fx.shareholders {
				combined := shares1[id].Add(shares2[id])
				err := scheme.Verify(combined, combinedVV)
				require.NoError(t, err,
					"combined share for ID %d must verify against Op'd VV", id)
			}
		})
	}
}

func TestVerificationVector_Op_Associative(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newFeldmanScheme(t, curve, fx.ac)

	out1, _ := dealFeldman(t, scheme, kw.NewSecret(field.FromUint64(1)))
	out2, _ := dealFeldman(t, scheme, kw.NewSecret(field.FromUint64(2)))
	out3, _ := dealFeldman(t, scheme, kw.NewSecret(field.FromUint64(3)))

	vv1 := out1.VerificationMaterial()
	vv2 := out2.VerificationMaterial()
	vv3 := out3.VerificationMaterial()

	// (vv1 + vv2) + vv3 == vv1 + (vv2 + vv3)
	left := vv1.Op(vv2).Op(vv3)
	right := vv1.Op(vv2.Op(vv3))
	require.True(t, left.Equal(right), "Op must be associative")
}

func TestVerificationVector_Op_Commutative(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newFeldmanScheme(t, curve, fx.ac)

	out1, _ := dealFeldman(t, scheme, kw.NewSecret(field.FromUint64(42)))
	out2, _ := dealFeldman(t, scheme, kw.NewSecret(field.FromUint64(77)))

	vv1 := out1.VerificationMaterial()
	vv2 := out2.VerificationMaterial()

	require.True(t, vv1.Op(vv2).Equal(vv2.Op(vv1)), "Op must be commutative")
}

// ---------------------------------------------------------------------------
// VerificationVector – CBOR round-trip
// ---------------------------------------------------------------------------

func TestVerificationVector_CBOR(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newFeldmanScheme(t, curve, fx.ac)
	secret := kw.NewSecret(field.FromUint64(999))

	out, _ := dealFeldman(t, scheme, secret)
	vv := out.VerificationMaterial()

	data, err := vv.MarshalCBOR()
	require.NoError(t, err)

	var decoded feldman.VerificationVector[*k256.Point, *k256.Scalar]
	err = decoded.UnmarshalCBOR(data)
	require.NoError(t, err)
	require.True(t, vv.Equal(&decoded))
}

func TestVerificationVector_CBOR_InvalidData(t *testing.T) {
	t.Parallel()

	var decoded feldman.VerificationVector[*k256.Point, *k256.Scalar]
	err := decoded.UnmarshalCBOR([]byte{0xff, 0x00, 0x01})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// ConvertShareToAdditive: sum of additive shares recovers the secret
// ---------------------------------------------------------------------------

func TestConvertShareToAdditive(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newFeldmanScheme(t, curve, fx.ac)
			secret := kw.NewSecret(field.FromUint64(42))
			_, shares := dealFeldman(t, scheme, secret)

			for _, qset := range fx.qualified {
				t.Run(formatIDs(qset), func(t *testing.T) {
					t.Parallel()
					quorum := newUnanimity(t, qset...)

					sum := field.Zero()
					for _, id := range qset {
						addShare, err := scheme.ConvertShareToAdditive(shares[id], quorum)
						require.NoError(t, err)
						sum = sum.Add(addShare.Value())
					}
					require.True(t, secret.Value().Equal(sum),
						"sum of additive shares must equal the secret")
				})
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ConvertShareToAdditive via additive.Scheme.Reconstruct
// ---------------------------------------------------------------------------

func TestConvertShareToAdditive_ViaAdditiveReconstruct(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newFeldmanScheme(t, curve, fx.ac)
			secret := kw.NewSecret(field.FromUint64(77))
			_, shares := dealFeldman(t, scheme, secret)

			for _, qset := range fx.qualified {
				t.Run(formatIDs(qset), func(t *testing.T) {
					t.Parallel()
					quorum := newUnanimity(t, qset...)

					additiveScheme, err := additive.NewScheme[*k256.Scalar](field, quorum)
					require.NoError(t, err)

					additiveShares := make([]*additive.Share[*k256.Scalar], len(qset))
					for i, id := range qset {
						addShare, err := scheme.ConvertShareToAdditive(shares[id], quorum)
						require.NoError(t, err)
						additiveShares[i] = addShare
					}

					reconstructed, err := additiveScheme.Reconstruct(additiveShares...)
					require.NoError(t, err)
					require.True(t, secret.Value().Equal(reconstructed.Value()))
				})
			}
		})
	}
}

// ---------------------------------------------------------------------------
// LiftedShare CBOR round-trip
// ---------------------------------------------------------------------------

func TestLiftedShare_CBOR(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	gen := curve.Generator()
	fx := thresholdFixture(t)
	scheme := newFeldmanScheme(t, curve, fx.ac)
	secret := kw.NewSecret(field.FromUint64(777))
	out, _ := dealFeldman(t, scheme, secret)

	for _, id := range fx.shareholders {
		t.Run(fmt.Sprintf("id=%d", id), func(t *testing.T) {
			t.Parallel()
			sh, ok := out.Shares().Get(id)
			require.True(t, ok)

			lifted, err := feldman.LiftShare(sh, gen)
			require.NoError(t, err)

			// Marshal the Feldman-level lifted share
			fls, err := feldman.NewLiftedShare[*k256.Point, *k256.Scalar](id, lifted.Value()...)
			require.NoError(t, err)

			data, err := fls.MarshalCBOR()
			require.NoError(t, err)

			var decoded feldman.LiftedShare[*k256.Point, *k256.Scalar]
			err = decoded.UnmarshalCBOR(data)
			require.NoError(t, err)
			require.Equal(t, fls.ID(), decoded.ID())
			require.Len(t, decoded.Value(), len(fls.Value()))
			for i := range fls.Value() {
				require.True(t, fls.Value()[i].Equal(decoded.Value()[i]))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BLS12-381 G1: field-agnostic verification
// ---------------------------------------------------------------------------

func TestBLS12381_G1(t *testing.T) {
	t.Parallel()

	g1 := bls12381.NewG1()
	field := bls12381.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme, err := feldman.NewScheme(g1, fx.ac)
			require.NoError(t, err)

			secret := kw.NewSecret(field.FromUint64(999999))
			out, err := scheme.Deal(secret, pcg.NewRandomised())
			require.NoError(t, err)
			ref := out.VerificationMaterial()

			m := make(map[sharing.ID]*kw.Share[*bls12381.Scalar])
			for id, sh := range out.Shares().Iter() {
				m[id] = sh
			}

			// Verify + reconstruct for every qualified set
			for _, qset := range fx.qualified {
				for _, id := range qset {
					require.NoError(t, scheme.Verify(m[id], ref))
				}
				reconstructed, err := scheme.Reconstruct(pickShares(m, qset...)...)
				require.NoError(t, err)
				require.True(t, secret.Equal(reconstructed))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BLS12-381 G2: verify on the second curve group too
// ---------------------------------------------------------------------------

func TestBLS12381_G2(t *testing.T) {
	t.Parallel()

	g2 := bls12381.NewG2()
	field := bls12381.NewScalarField()

	fx := thresholdFixture(t)
	scheme, err := feldman.NewScheme(g2, fx.ac)
	require.NoError(t, err)

	secret := kw.NewSecret(field.FromUint64(54321))
	out, err := scheme.Deal(secret, pcg.NewRandomised())
	require.NoError(t, err)
	ref := out.VerificationMaterial()

	m := make(map[sharing.ID]*kw.Share[*bls12381.Scalar])
	for id, sh := range out.Shares().Iter() {
		m[id] = sh
	}

	for _, qset := range fx.qualified {
		for _, id := range qset {
			require.NoError(t, scheme.Verify(m[id], ref))
		}
		reconstructed, err := scheme.Reconstruct(pickShares(m, qset...)...)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	}
}

// ---------------------------------------------------------------------------
// Dahlgren attack prevention: an adversary extends the verification vector
// with extra group elements, hoping to inject additional degrees of freedom
// that let a corrupted share pass verification. The left module action M * V
// enforces dim(V) == MSP.D(), so the extended vector must be rejected.
//
// See https://blog.trailofbits.com/2024/02/20/breaking-the-shared-key-in-threshold-signature-schemes/
// ---------------------------------------------------------------------------

func TestDahlgrenAttack_ExtendedVerificationVector(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	gen := curve.Generator()

	fx := largeThresholdFixture(t) // threshold(4,7) → D=4
	scheme := newFeldmanScheme(t, curve, fx.ac)
	secret := kw.NewSecret(field.FromUint64(42))
	prng := pcg.NewRandomised()

	out, df, err := scheme.DealAndRevealDealerFunc(secret, prng)
	require.NoError(t, err)

	// Build an extended verification vector: the honest D entries plus one
	// extra random group element (D+1 rows × 1 col).
	r := df.RandomColumn()
	d, _ := r.Dimensions()
	extraScalar, err := field.Random(prng)
	require.NoError(t, err)
	extMod, err := mat.NewMatrixModule(uint(d+1), 1, field)
	require.NoError(t, err)
	entries := make([]FE, d+1)
	for i := range d {
		entries[i], err = r.Get(i, 0)
		require.NoError(t, err)
	}
	entries[d] = extraScalar
	extCol, err := extMod.NewRowMajor(entries...)
	require.NoError(t, err)
	extendedVV, err := mat.Lift(extCol, gen)
	require.NoError(t, err)

	// Wrap without MSP so the constructor doesn't reject; Verify will reject
	// via the dimension check in the left module action.
	extendedRef, err := feldman.NewVerificationVector[*k256.Point](extendedVV, nil)
	require.NoError(t, err)

	// Verify must fail: the extended V has dimension D+1, but M has D columns.
	sh, ok := out.Shares().Get(fx.shareholders[0])
	require.True(t, ok)
	err = scheme.Verify(sh, extendedRef)
	require.Error(t, err, "extended verification vector must be rejected (Dahlgren attack)")
}

// ---------------------------------------------------------------------------
// Arbitrary (non-sequential) shareholder IDs
// ---------------------------------------------------------------------------

func TestArbitraryIDs(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	ac, err := threshold.NewThresholdAccessStructure(2, shareholders(10, 100, 1000))
	require.NoError(t, err)
	scheme := newFeldmanScheme(t, curve, ac)

	secret := kw.NewSecret(field.FromUint64(54321))
	out, shares := dealFeldman(t, scheme, secret)
	ref := out.VerificationMaterial()

	for _, qset := range [][]sharing.ID{{10, 100}, {10, 1000}, {100, 1000}, {10, 100, 1000}} {
		for _, id := range qset {
			require.NoError(t, scheme.Verify(shares[id], ref))
		}
		reconstructed, err := scheme.Reconstruct(pickShares(shares, qset...)...)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	}
}

// ---------------------------------------------------------------------------
// DealRandomAndRevealDealerFunc: lifted secret matches [s]G
// ---------------------------------------------------------------------------

func TestDealRandomAndRevealDealerFunc_LiftedSecret(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	gen := curve.Generator()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newFeldmanScheme(t, curve, fx.ac)

			out, secret, df, err := scheme.DealRandomAndRevealDealerFunc(pcg.NewRandomised())
			require.NoError(t, err)
			require.NotNil(t, out)

			// The lifted secret (first element of V for standard target) should
			// equal [secret]G.
			ldf, err := feldman.NewLiftedDealerFunc(out.VerificationMaterial(), df.MSP())
			require.NoError(t, err)
			liftedSecret := ldf.LiftedSecret()
			expected := gen.ScalarOp(secret.Value())
			require.True(t, expected.Equal(liftedSecret.Value()),
				"V[0] must equal [secret]G")
		})
	}
}

// ---------------------------------------------------------------------------
// Multi-row shareholders (non-ideal MSP): verification still works
// CNF access structures produce non-ideal MSPs where shareholders own
// multiple MSP rows.
// ---------------------------------------------------------------------------

func TestVerify_MultiRowShareholders(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()

	fx := cnfThreeClauseFixture(t) // non-ideal MSP
	scheme := newFeldmanScheme(t, curve, fx.ac)
	secret := kw.NewSecret(field.FromUint64(31337))
	out, shares := dealFeldman(t, scheme, secret)
	ref := out.VerificationMaterial()

	// Confirm multi-row shares
	for _, id := range fx.shareholders {
		require.Greater(t, len(shares[id].Value()), 1,
			"shareholder %d should own more than one MSP row", id)
	}

	// Verification must still pass
	for _, id := range fx.shareholders {
		require.NoError(t, scheme.Verify(shares[id], ref),
			"multi-row share verification failed for ID %d", id)
	}

	// Reconstruct + verify
	for _, qset := range fx.qualified {
		reconstructed, err := scheme.ReconstructAndVerify(ref, pickShares(shares, qset...)...)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	}
}

// ---------------------------------------------------------------------------
// Deal error cases
// ---------------------------------------------------------------------------

func TestDeal_NilSecret(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	fx := thresholdFixture(t)
	scheme := newFeldmanScheme(t, curve, fx.ac)

	_, err := scheme.Deal(nil, pcg.NewRandomised())
	require.Error(t, err)
}

func TestDeal_NilPRNG(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newFeldmanScheme(t, curve, fx.ac)

	_, err := scheme.Deal(kw.NewSecret(field.One()), nil)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// LiftDealerFunc – construction and error cases
// ---------------------------------------------------------------------------

func TestLiftDealerFunc_NilDealerFunc(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	_, err := feldman.LiftDealerFunc(nil, curve.Generator())
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrIsNil)
}

func TestLiftDealerFunc_NilBasePoint(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newFeldmanScheme(t, curve, fx.ac)

	_, df, err := scheme.DealAndRevealDealerFunc(kw.NewSecret(field.One()), pcg.NewRandomised())
	require.NoError(t, err)

	_, err = feldman.LiftDealerFunc[*k256.Point](df, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrIsNil)
}

func TestLiftDealerFunc_LiftedSecretMatchesScalarMul(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	gen := curve.Generator()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newFeldmanScheme(t, curve, fx.ac)
			secret := kw.NewSecret(field.FromUint64(42))

			_, df, err := scheme.DealAndRevealDealerFunc(secret, pcg.NewRandomised())
			require.NoError(t, err)

			ldf, err := feldman.LiftDealerFunc(df, gen)
			require.NoError(t, err)

			// LiftedSecret should equal gen * secret
			expected := gen.ScalarOp(secret.Value())
			require.True(t, expected.Equal(ldf.LiftedSecret().Value()),
				"lifted secret should be basePoint * secret")
		})
	}
}

func TestLiftDealerFunc_LiftedShareMatchesManualLift(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	gen := curve.Generator()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newFeldmanScheme(t, curve, fx.ac)
			secret := kw.NewSecret(field.FromUint64(77))

			_, df, err := scheme.DealAndRevealDealerFunc(secret, pcg.NewRandomised())
			require.NoError(t, err)

			ldf, err := feldman.LiftDealerFunc(df, gen)
			require.NoError(t, err)

			for _, id := range fx.shareholders {
				liftedShare, err := ldf.ShareOf(id)
				require.NoError(t, err)

				// Manually lift the scalar share
				scalarShare, err := df.ShareOf(id)
				require.NoError(t, err)
				manualLift, err := feldman.LiftShare(scalarShare, gen)
				require.NoError(t, err)

				require.True(t, liftedShare.Equal(manualLift),
					"LiftDealerFunc.ShareOf(%d) must match LiftShare of scalar share", id)
			}
		})
	}
}

func TestLiftDealerFunc_ShareOfNonExistentID(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newFeldmanScheme(t, curve, fx.ac)

	_, df, err := scheme.DealAndRevealDealerFunc(kw.NewSecret(field.One()), pcg.NewRandomised())
	require.NoError(t, err)

	ldf, err := feldman.LiftDealerFunc(df, curve.Generator())
	require.NoError(t, err)

	_, err = ldf.ShareOf(999)
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrMembership)
}

func TestLiftDealerFunc_Accessors(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newFeldmanScheme(t, curve, fx.ac)

	_, df, err := scheme.DealAndRevealDealerFunc(kw.NewSecret(field.FromUint64(3)), pcg.NewRandomised())
	require.NoError(t, err)

	ldf, err := feldman.LiftDealerFunc(df, curve.Generator())
	require.NoError(t, err)

	require.NotNil(t, ldf.VerificationVector())
	require.NotNil(t, ldf.MSP())
	require.NotNil(t, ldf.Lambda())
}

// ---------------------------------------------------------------------------
// NewLiftedDealerFunc – construction and error cases
// ---------------------------------------------------------------------------

func TestNewLiftedDealerFunc_NilVerificationVector(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newFeldmanScheme(t, curve, fx.ac)

	_, df, err := scheme.DealAndRevealDealerFunc(kw.NewSecret(field.One()), pcg.NewRandomised())
	require.NoError(t, err)

	_, err = feldman.NewLiftedDealerFunc[*k256.Point](nil, df.MSP())
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrIsNil)
}

func TestNewLiftedDealerFunc_NilMSP(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newFeldmanScheme(t, curve, fx.ac)

	_, df, err := scheme.DealAndRevealDealerFunc(kw.NewSecret(field.One()), pcg.NewRandomised())
	require.NoError(t, err)

	vvv, err := mat.Lift(df.RandomColumn(), curve.Generator())
	require.NoError(t, err)

	vv, err := feldman.NewVerificationVector(vvv, nil)
	require.NoError(t, err)

	_, err = feldman.NewLiftedDealerFunc(vv, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrIsNil)
}

func TestNewLiftedDealerFunc_ConsistentWithLiftDealerFunc(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	gen := curve.Generator()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newFeldmanScheme(t, curve, fx.ac)
			secret := kw.NewSecret(field.FromUint64(42))

			_, df, err := scheme.DealAndRevealDealerFunc(secret, pcg.NewRandomised())
			require.NoError(t, err)

			// Method 1: LiftDealerFunc
			ldf1, err := feldman.LiftDealerFunc(df, gen)
			require.NoError(t, err)

			// Method 2: NewLiftedDealerFunc from verification vector
			vvv, err := mat.Lift(df.RandomColumn(), gen)
			require.NoError(t, err)
			vv, err := feldman.NewVerificationVector(vvv, df.MSP())
			require.NoError(t, err)
			ldf2, err := feldman.NewLiftedDealerFunc(vv, df.MSP())
			require.NoError(t, err)

			// Both should produce the same lifted secret
			require.True(t, ldf1.LiftedSecret().Equal(ldf2.LiftedSecret()),
				"LiftDealerFunc and NewLiftedDealerFunc must produce the same lifted secret")

			// Both should produce the same lifted shares
			for _, id := range fx.shareholders {
				sh1, err := ldf1.ShareOf(id)
				require.NoError(t, err)
				sh2, err := ldf2.ShareOf(id)
				require.NoError(t, err)
				require.True(t, sh1.Equal(sh2),
					"lifted shares for ID %d must match between LiftDealerFunc and NewLiftedDealerFunc", id)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// type alias to shorten generic constraints in tamper helpers
// ---------------------------------------------------------------------------

type FE = *k256.Scalar
