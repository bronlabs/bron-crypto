package kw_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
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
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func shareholders(ids ...sharing.ID) ds.Set[sharing.ID] {
	return hashset.NewComparable(ids...).Freeze()
}

func newKWScheme[FE algebra.PrimeFieldElement[FE]](tb testing.TB, f algebra.PrimeField[FE], ac accessstructures.Monotone) *kw.Scheme[FE] {
	tb.Helper()
	scheme, err := kw.NewScheme(f, ac)
	require.NoError(tb, err)
	return scheme
}

func dealAndCollect[FE algebra.PrimeFieldElement[FE]](tb testing.TB, scheme *kw.Scheme[FE], secret *kw.Secret[FE]) map[sharing.ID]*kw.Share[FE] {
	tb.Helper()
	out, err := scheme.Deal(secret, pcg.NewRandomised())
	require.NoError(tb, err)
	m := make(map[sharing.ID]*kw.Share[FE])
	for id, sh := range out.Shares().Iter() {
		m[id] = sh
	}
	return m
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
	ac           accessstructures.Monotone
	qualified    [][]sharing.ID // sets that MUST reconstruct
	unqualified  [][]sharing.ID // sets that MUST be rejected
	shareholders []sharing.ID   // all shareholders
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
	// Qualified iff not subset of any MUS ⟹ need someone outside {1,2} AND outside {3,4}
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
			{1, 3},    // outside {1,2}: 3; outside {3,4}: 1; outside {5}: 1,3
			{3, 5},    // outside {1,2}: 3,5; outside {3,4}: 5; outside {5}: 3
			{1, 3, 4}, // outside {1,2}: 3,4; outside {3,4}: 1; outside {5}: all
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
	// L0 {1,2,3} cumulative threshold=2, L1 {4,5,6} cumulative threshold=4.
	ac, err := hierarchical.NewHierarchicalConjunctiveThresholdAccessStructure(
		hierarchical.WithLevel(2, 1, 2, 3),
		hierarchical.WithLevel(4, 4, 5, 6),
	)
	require.NoError(t, err)
	return acFixture{
		name: "hierarchical(2,4)",
		ac:   ac,
		qualified: [][]sharing.ID{
			{1, 2, 4, 5},       // 2 from L0, 2 from L1
			{1, 2, 3, 4},       // 3 from L0, 1 from L1
			{2, 3, 5, 6},       // 2 from L0, 2 from L1
			{1, 2, 3, 4, 5, 6}, // everyone
		},
		unqualified: [][]sharing.ID{
			{1, 4, 5},    // only 1 from L0
			{4, 5, 6},    // 0 from L0
			{1, 2, 3},    // only 3 total, need 4
			{3, 4, 5, 6}, // only 1 from L0
		},
		shareholders: []sharing.ID{1, 2, 3, 4, 5, 6},
	}
}

func hierarchicalThreeLevelFixture(t *testing.T) acFixture {
	t.Helper()
	// L0 {1,2} t=1, L1 {3,4} t=2, L2 {5,6} t=4.
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
			{1, 3, 5, 6},       // 1+1+2
			{2, 4, 5, 6},       // 1+1+2
			{1, 2, 3, 4},       // 2+2+0
			{1, 2, 3, 4, 5, 6}, // everyone
		},
		unqualified: [][]sharing.ID{
			{3, 5, 6}, // 0 from L0
			{1, 5, 6}, // only 1 from L0∪L1
			{5, 6},    // 0 from L0
			{1, 3, 5}, // only 3 total, need 4
		},
		shareholders: []sharing.ID{1, 2, 3, 4, 5, 6},
	}
}

func boolexprThreeBranchFixture(t *testing.T) acFixture {
	t.Helper()
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

func boolexprExampleCFixture(t *testing.T) acFixture {
	t.Helper()
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
		name: "boolexpr(example-c)",
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
		boolexprExampleCFixture(t),
	}
}

// ---------------------------------------------------------------------------
// NewScheme
// ---------------------------------------------------------------------------

func TestNewScheme(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	t.Run("valid construction with each access structure", func(t *testing.T) {
		t.Parallel()
		for _, fx := range allFixtures(t) {
			t.Run(fx.name, func(t *testing.T) {
				t.Parallel()
				scheme, err := kw.NewScheme(field, fx.ac)
				require.NoError(t, err)
				require.NotNil(t, scheme)
				require.Equal(t, kw.Name, scheme.Name())
				require.Equal(t, len(fx.shareholders), scheme.Shareholders().Size())
			})
		}
	})

	t.Run("nil field", func(t *testing.T) {
		t.Parallel()
		ac, err := threshold.NewThresholdAccessStructure(2, shareholders(1, 2, 3))
		require.NoError(t, err)
		_, err = kw.NewScheme[*k256.Scalar](nil, ac)
		require.Error(t, err)
	})

	t.Run("nil access structure", func(t *testing.T) {
		t.Parallel()
		_, err := kw.NewScheme[*k256.Scalar](field, nil)
		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// Deal
// ---------------------------------------------------------------------------

func TestDeal(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newKWScheme(t, field, fx.ac)

			t.Run("constant secret", func(t *testing.T) {
				t.Parallel()
				secret := kw.NewSecret(field.FromUint64(42))
				out, err := scheme.Deal(secret, pcg.NewRandomised())
				require.NoError(t, err)
				require.Equal(t, len(fx.shareholders), out.Shares().Size())
			})

			t.Run("zero secret", func(t *testing.T) {
				t.Parallel()
				secret := kw.NewSecret(field.Zero())
				shares := dealAndCollect(t, scheme, secret)
				reconstructed, err := scheme.Reconstruct(pickShares(shares, fx.qualified[0]...)...)
				require.NoError(t, err)
				require.True(t, secret.Equal(reconstructed))
			})

			t.Run("one secret", func(t *testing.T) {
				t.Parallel()
				secret := kw.NewSecret(field.One())
				shares := dealAndCollect(t, scheme, secret)
				reconstructed, err := scheme.Reconstruct(pickShares(shares, fx.qualified[0]...)...)
				require.NoError(t, err)
				require.True(t, secret.Equal(reconstructed))
			})

			t.Run("nil secret", func(t *testing.T) {
				t.Parallel()
				_, err := scheme.Deal(nil, pcg.NewRandomised())
				require.Error(t, err)
				require.ErrorIs(t, err, sharing.ErrIsNil)
			})

			t.Run("nil prng", func(t *testing.T) {
				t.Parallel()
				secret := kw.NewSecret(field.FromUint64(1))
				_, err := scheme.Deal(secret, nil)
				require.Error(t, err)
				require.ErrorIs(t, err, sharing.ErrIsNil)
			})

			t.Run("exhausted prng", func(t *testing.T) {
				t.Parallel()
				secret := kw.NewSecret(field.FromUint64(1))
				_, err := scheme.Deal(secret, bytes.NewReader([]byte{0}))
				require.Error(t, err)
			})
		})
	}
}

// ---------------------------------------------------------------------------
// DealRandom
// ---------------------------------------------------------------------------

func TestDealRandom(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newKWScheme(t, field, fx.ac)

			t.Run("returns valid output", func(t *testing.T) {
				t.Parallel()
				out, secret, err := scheme.DealRandom(pcg.NewRandomised())
				require.NoError(t, err)
				require.NotNil(t, out)
				require.NotNil(t, secret)
				require.Equal(t, len(fx.shareholders), out.Shares().Size())
			})

			t.Run("consecutive calls produce different secrets", func(t *testing.T) {
				t.Parallel()
				prng := pcg.NewRandomised()
				_, s1, err := scheme.DealRandom(prng)
				require.NoError(t, err)
				_, s2, err := scheme.DealRandom(prng)
				require.NoError(t, err)
				require.False(t, s1.Equal(s2))
			})

			t.Run("nil prng", func(t *testing.T) {
				t.Parallel()
				out, secret, err := scheme.DealRandom(nil)
				require.Error(t, err)
				require.Nil(t, out)
				require.Nil(t, secret)
			})
		})
	}
}

// ---------------------------------------------------------------------------
// DealAndRevealDealerFunc
// ---------------------------------------------------------------------------

func TestDealAndRevealDealerFunc(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newKWScheme(t, field, fx.ac)

			t.Run("returns shares and dealer func", func(t *testing.T) {
				t.Parallel()
				secret := kw.NewSecret(field.FromUint64(77))
				out, df, err := scheme.DealAndRevealDealerFunc(secret, pcg.NewRandomised())
				require.NoError(t, err)
				require.NotNil(t, out)
				require.NotNil(t, df)
				require.Equal(t, len(fx.shareholders), out.Shares().Size())
			})

			t.Run("nil secret", func(t *testing.T) {
				t.Parallel()
				out, df, err := scheme.DealAndRevealDealerFunc(nil, pcg.NewRandomised())
				require.Error(t, err)
				require.ErrorIs(t, err, sharing.ErrIsNil)
				require.Nil(t, out)
				require.Nil(t, df)
			})

			t.Run("nil prng", func(t *testing.T) {
				t.Parallel()
				secret := kw.NewSecret(field.FromUint64(1))
				out, df, err := scheme.DealAndRevealDealerFunc(secret, nil)
				require.Error(t, err)
				require.ErrorIs(t, err, sharing.ErrIsNil)
				require.Nil(t, out)
				require.Nil(t, df)
			})
		})
	}
}

// ---------------------------------------------------------------------------
// DealRandomAndRevealDealerFunc
// ---------------------------------------------------------------------------

func TestDealRandomAndRevealDealerFunc(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newKWScheme(t, field, fx.ac)

			t.Run("returns all components", func(t *testing.T) {
				t.Parallel()
				out, secret, df, err := scheme.DealRandomAndRevealDealerFunc(pcg.NewRandomised())
				require.NoError(t, err)
				require.NotNil(t, out)
				require.NotNil(t, secret)
				require.NotNil(t, df)

				// reconstruction should match returned secret
				shares := make([]*kw.Share[*k256.Scalar], 0)
				for _, sh := range out.Shares().Values() {
					shares = append(shares, sh)
				}
				// use first qualified set
				m := make(map[sharing.ID]*kw.Share[*k256.Scalar])
				for id, sh := range out.Shares().Iter() {
					m[id] = sh
				}
				reconstructed, err := scheme.Reconstruct(pickShares(m, fx.qualified[0]...)...)
				require.NoError(t, err)
				require.True(t, secret.Equal(reconstructed))
			})

			t.Run("nil prng", func(t *testing.T) {
				t.Parallel()
				out, secret, df, err := scheme.DealRandomAndRevealDealerFunc(nil)
				require.Error(t, err)
				require.Nil(t, out)
				require.Nil(t, secret)
				require.Nil(t, df)
			})
		})
	}
}

// ---------------------------------------------------------------------------
// Reconstruct – qualified / unqualified exhaustive check
// ---------------------------------------------------------------------------

func TestReconstruct_QualifiedSets(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newKWScheme(t, field, fx.ac)
			secret := kw.NewSecret(field.FromUint64(123456))
			shares := dealAndCollect(t, scheme, secret)

			for _, qset := range fx.qualified {
				t.Run(formatIDs(qset), func(t *testing.T) {
					t.Parallel()
					reconstructed, err := scheme.Reconstruct(pickShares(shares, qset...)...)
					require.NoError(t, err)
					require.True(t, secret.Equal(reconstructed))
				})
			}
		})
	}
}

func TestReconstruct_UnqualifiedSets(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newKWScheme(t, field, fx.ac)
			secret := kw.NewSecret(field.FromUint64(654321))
			shares := dealAndCollect(t, scheme, secret)

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

func TestReconstruct_NoShares(t *testing.T) {
	t.Parallel()
	field := k256.NewScalarField()
	scheme := newKWScheme(t, field, thresholdFixture(t).ac)
	_, err := scheme.Reconstruct()
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrValue)
}

// ---------------------------------------------------------------------------
// Correctness: random secrets round-trip through deal/reconstruct
// ---------------------------------------------------------------------------

func TestRoundTrip_RandomSecrets(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	prng := pcg.NewRandomised()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newKWScheme(t, field, fx.ac)

			for range 5 {
				val, err := field.Random(prng)
				require.NoError(t, err)
				secret := kw.NewSecret(val)
				shares := dealAndCollect(t, scheme, secret)

				for _, qset := range fx.qualified {
					reconstructed, err := scheme.Reconstruct(pickShares(shares, qset...)...)
					require.NoError(t, err)
					require.True(t, secret.Equal(reconstructed))
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Homomorphism: share addition mirrors secret addition
// ---------------------------------------------------------------------------

func TestHomomorphicAddition(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newKWScheme(t, field, fx.ac)

			s1 := kw.NewSecret(field.FromUint64(500))
			s2 := kw.NewSecret(field.FromUint64(300))

			shares1 := dealAndCollect(t, scheme, s1)
			shares2 := dealAndCollect(t, scheme, s2)

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
// Homomorphism: scalar multiplication mirrors secret scaling
// ---------------------------------------------------------------------------

func TestHomomorphicScalarMul(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newKWScheme(t, field, fx.ac)

			s := kw.NewSecret(field.FromUint64(42))
			scalar := field.FromUint64(7)

			shares := dealAndCollect(t, scheme, s)

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
// Privacy: any t-1 threshold shares are uniformly distributed (statistical)
//
// For the threshold(2,3) case, every single share alone should reveal no
// information about the secret. We test this by dealing two different secrets
// and verifying that the individual share vectors are *different* (they are
// randomised independently), which is a basic smoke-test for privacy.
// ---------------------------------------------------------------------------

func TestPrivacy_SingleShareRevealsNothing(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newKWScheme(t, field, fx.ac)

	s1 := kw.NewSecret(field.FromUint64(100))
	s2 := kw.NewSecret(field.FromUint64(200))

	shares1 := dealAndCollect(t, scheme, s1)
	shares2 := dealAndCollect(t, scheme, s2)

	// For each shareholder, their share from s1 and s2 should differ
	// (with overwhelming probability since the randomness is fresh).
	for _, id := range fx.shareholders {
		require.False(t, shares1[id].Equal(shares2[id]),
			"shares for ID %d should be randomised independently of the secret", id)
	}
}

// ---------------------------------------------------------------------------
// Determinism: same PRNG seed produces identical shares
// ---------------------------------------------------------------------------

func TestDeterminism(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newKWScheme(t, field, fx.ac)
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
}

// ---------------------------------------------------------------------------
// BLS12-381 field: verify the scheme is field-agnostic
// ---------------------------------------------------------------------------

func TestBLS12381(t *testing.T) {
	t.Parallel()

	field := bls12381.NewScalarField()
	ac, err := threshold.NewThresholdAccessStructure(2, shareholders(1, 2, 3))
	require.NoError(t, err)
	scheme := newKWScheme(t, field, ac)

	secret := kw.NewSecret(field.FromUint64(999999))
	out, err := scheme.Deal(secret, pcg.NewRandomised())
	require.NoError(t, err)

	m := make(map[sharing.ID]*kw.Share[*bls12381.Scalar])
	for id, sh := range out.Shares().Iter() {
		m[id] = sh
	}

	for _, qset := range [][]sharing.ID{{1, 2}, {1, 3}, {2, 3}, {1, 2, 3}} {
		shares := make([]*kw.Share[*bls12381.Scalar], len(qset))
		for i, id := range qset {
			shares[i] = m[id]
		}
		reconstructed, err := scheme.Reconstruct(shares...)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	}
}

// ---------------------------------------------------------------------------
// Share type: CBOR serialisation round-trip
// ---------------------------------------------------------------------------

func TestShareCBOR(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newKWScheme(t, field, fx.ac)
	secret := kw.NewSecret(field.FromUint64(777))
	shares := dealAndCollect(t, scheme, secret)

	for _, id := range fx.shareholders {
		t.Run(formatIDs([]sharing.ID{id}), func(t *testing.T) {
			t.Parallel()
			sh := shares[id]

			data, err := sh.MarshalCBOR()
			require.NoError(t, err)

			var decoded kw.Share[*k256.Scalar]
			err = decoded.UnmarshalCBOR(data)
			require.NoError(t, err)
			require.True(t, sh.Equal(&decoded))
		})
	}

	t.Run("invalid CBOR", func(t *testing.T) {
		t.Parallel()
		var decoded kw.Share[*k256.Scalar]
		err := decoded.UnmarshalCBOR([]byte{0xff, 0x00, 0x01})
		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// Share type: Equal, HashCode, Add, ScalarMul
// ---------------------------------------------------------------------------

func TestShareMethods(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newKWScheme(t, field, fx.ac)
	secret := kw.NewSecret(field.FromUint64(42))
	shares := dealAndCollect(t, scheme, secret)

	sh1 := shares[1]
	sh2 := shares[2]

	t.Run("Equal self", func(t *testing.T) {
		t.Parallel()
		require.True(t, sh1.Equal(sh1))
	})

	t.Run("not equal different ID", func(t *testing.T) {
		t.Parallel()
		require.False(t, sh1.Equal(sh2))
	})

	t.Run("not equal nil", func(t *testing.T) {
		t.Parallel()
		require.False(t, sh1.Equal(nil))
	})

	t.Run("HashCode differs for different shares", func(t *testing.T) {
		t.Parallel()
		require.NotEqual(t, sh1.HashCode(), sh2.HashCode())
	})

	t.Run("Op is Add", func(t *testing.T) {
		t.Parallel()
		// Create second dealing for same shareholder to test Add
		secret2 := kw.NewSecret(field.FromUint64(10))
		shares2 := dealAndCollect(t, scheme, secret2)
		added := sh1.Add(shares2[1])
		opped := sh1.Op(shares2[1])
		require.True(t, added.Equal(opped))
	})
}

// ---------------------------------------------------------------------------
// Secret type
// ---------------------------------------------------------------------------

func TestSecret(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	s1 := kw.NewSecret(field.FromUint64(10))
	s2 := kw.NewSecret(field.FromUint64(20))
	s1Copy := kw.NewSecret(field.FromUint64(10))

	require.True(t, s1.Equal(s1Copy))
	require.False(t, s1.Equal(s2))
	require.False(t, s1.Equal(nil))
	require.True(t, s1.Value().Equal(field.FromUint64(10)))

	cloned := s1.Clone()
	require.True(t, s1.Equal(cloned))
}

// ---------------------------------------------------------------------------
// Arbitrary (non-sequential) shareholder IDs
// ---------------------------------------------------------------------------

func TestArbitraryIDs(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	ac, err := threshold.NewThresholdAccessStructure(2, shareholders(10, 100, 1000))
	require.NoError(t, err)
	scheme := newKWScheme(t, field, ac)

	secret := kw.NewSecret(field.FromUint64(54321))
	shares := dealAndCollect(t, scheme, secret)

	for _, qset := range [][]sharing.ID{{10, 100}, {10, 1000}, {100, 1000}, {10, 100, 1000}} {
		reconstructed, err := scheme.Reconstruct(pickShares(shares, qset...)...)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	}
}

// ---------------------------------------------------------------------------
// NewShare constructor
// ---------------------------------------------------------------------------

func TestNewShare(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		sh, err := kw.NewShare(1, field.One())
		require.NoError(t, err)
		require.Equal(t, sharing.ID(1), sh.ID())
	})

	t.Run("zero ID", func(t *testing.T) {
		t.Parallel()
		_, err := kw.NewShare(0, field.One())
		require.Error(t, err)
	})

	t.Run("nil value", func(t *testing.T) {
		t.Parallel()
		_, err := kw.NewShare[*k256.Scalar](1)
		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// ConvertShareToAdditive – sum of additive shares recovers the secret
// ---------------------------------------------------------------------------

func TestConvertShareToAdditive_SumRecoversSecret(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newKWScheme(t, field, fx.ac)
			secret := kw.NewSecret(field.FromUint64(42))
			shares := dealAndCollect(t, scheme, secret)

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

func TestConvertShareToAdditive_RandomSecrets(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newKWScheme(t, field, fx.ac)
			prng := pcg.NewRandomised()

			for range 5 {
				val, err := field.Random(prng)
				require.NoError(t, err)
				secret := kw.NewSecret(val)
				shares := dealAndCollect(t, scheme, secret)

				for _, qset := range fx.qualified {
					quorum := newUnanimity(t, qset...)

					sum := field.Zero()
					for _, id := range qset {
						addShare, err := scheme.ConvertShareToAdditive(shares[id], quorum)
						require.NoError(t, err)
						sum = sum.Add(addShare.Value())
					}
					require.True(t, secret.Value().Equal(sum),
						"sum of additive shares must equal the secret for quorum %v", qset)
				}
			}
		})
	}
}

func TestConvertShareToAdditive_ConsistentAcrossQuorums(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	fx := thresholdFixture(t) // has multiple qualified sets
	scheme := newKWScheme(t, field, fx.ac)
	secret := kw.NewSecret(field.FromUint64(999))
	shares := dealAndCollect(t, scheme, secret)

	// Every qualified quorum should produce additive shares that sum to
	// the same original secret.
	for _, qset := range fx.qualified {
		quorum := newUnanimity(t, qset...)

		sum := field.Zero()
		for _, id := range qset {
			addShare, err := scheme.ConvertShareToAdditive(shares[id], quorum)
			require.NoError(t, err)
			sum = sum.Add(addShare.Value())
		}
		require.True(t, secret.Value().Equal(sum),
			"quorum %v must reconstruct the same secret", qset)
	}
}

func TestConvertShareToAdditive_ViaAdditiveReconstruct(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newKWScheme(t, field, fx.ac)
	secret := kw.NewSecret(field.FromUint64(77))
	shares := dealAndCollect(t, scheme, secret)

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
			require.True(t, secret.Value().Equal(reconstructed.Value()),
				"additive reconstruction must recover the KW secret")
		})
	}
}

func TestConvertShareToAdditive_ZeroSecret(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newKWScheme(t, field, fx.ac)
	secret := kw.NewSecret(field.Zero())
	shares := dealAndCollect(t, scheme, secret)

	qset := fx.qualified[0]
	quorum := newUnanimity(t, qset...)

	sum := field.Zero()
	for _, id := range qset {
		addShare, err := scheme.ConvertShareToAdditive(shares[id], quorum)
		require.NoError(t, err)
		sum = sum.Add(addShare.Value())
	}
	require.True(t, field.Zero().Equal(sum),
		"additive shares of a zero secret must sum to zero")
}

func TestConvertShareToAdditive_IndividualShareRevealsNothing(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newKWScheme(t, field, fx.ac)

	// Deal two different secrets.
	s1 := kw.NewSecret(field.FromUint64(100))
	s2 := kw.NewSecret(field.FromUint64(200))

	shares1 := dealAndCollect(t, scheme, s1)
	shares2 := dealAndCollect(t, scheme, s2)

	qset := fx.qualified[0]
	quorum := newUnanimity(t, qset...)

	// Each shareholder's additive share should differ between the two dealings
	// (with overwhelming probability) — it inherits fresh randomness.
	for _, id := range qset {
		a1, err := scheme.ConvertShareToAdditive(shares1[id], quorum)
		require.NoError(t, err)
		a2, err := scheme.ConvertShareToAdditive(shares2[id], quorum)
		require.NoError(t, err)
		require.False(t, a1.Value().Equal(a2.Value()),
			"additive share for ID %d should differ between dealings", id)
	}
}

func TestConvertShareToAdditive_BLS12381(t *testing.T) {
	t.Parallel()

	field := bls12381.NewScalarField()
	ac, err := threshold.NewThresholdAccessStructure(2, shareholders(1, 2, 3))
	require.NoError(t, err)
	scheme := newKWScheme(t, field, ac)

	secret := kw.NewSecret(field.FromUint64(12345))
	shares := dealAndCollect(t, scheme, secret)

	for _, qset := range [][]sharing.ID{{1, 2}, {1, 3}, {2, 3}, {1, 2, 3}} {
		quorum := newUnanimity(t, qset...)

		sum := field.Zero()
		for _, id := range qset {
			addShare, err := scheme.ConvertShareToAdditive(shares[id], quorum)
			require.NoError(t, err)
			sum = sum.Add(addShare.Value())
		}
		require.True(t, secret.Value().Equal(sum),
			"BLS12-381 additive shares must sum to the secret for quorum %v", qset)
	}
}

// ---------------------------------------------------------------------------
// ConvertShareToAdditive – error cases
// ---------------------------------------------------------------------------

func TestConvertShareToAdditive_NilShare(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newKWScheme(t, field, fx.ac)
	quorum := newUnanimity(t, fx.qualified[0]...)

	_, err := scheme.ConvertShareToAdditive(nil, quorum)
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrIsNil)
}

func TestConvertShareToAdditive_NilQuorum(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newKWScheme(t, field, fx.ac)
	secret := kw.NewSecret(field.FromUint64(1))
	shares := dealAndCollect(t, scheme, secret)

	_, err := scheme.ConvertShareToAdditive(shares[1], nil)
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrIsNil)
}

func TestConvertShareToAdditive_ShareNotInQuorum(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	fx := thresholdFixture(t) // shareholders {1,2,3}
	scheme := newKWScheme(t, field, fx.ac)
	secret := kw.NewSecret(field.FromUint64(1))
	shares := dealAndCollect(t, scheme, secret)

	// Build a quorum that does not include shareholder 3.
	quorum := newUnanimity(t, 1, 2)

	_, err := scheme.ConvertShareToAdditive(shares[3], quorum)
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrMembership)
}

func TestConvertShareToAdditive_MultiRowShareholders(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	// cnf({1,2},{3,4},{5}) gives every shareholder ≥ 2 MSP rows because each
	// shareholder appears in at least two of the three clause complements.
	fx := cnfThreeClauseFixture(t)
	scheme := newKWScheme(t, field, fx.ac)
	secret := kw.NewSecret(field.FromUint64(31337))
	shares := dealAndCollect(t, scheme, secret)

	// Verify that shareholders actually own multiple rows.
	for _, id := range fx.shareholders {
		require.Greater(t, len(shares[id].Value()), 1,
			"shareholder %d should own more than one MSP row", id)
	}

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
				"additive shares from multi-row holders must still sum to the secret")
		})
	}
}

func TestConvertShareToAdditive_QuorumNotQualified(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	// cnf({1,2},{3,4}): {1,2} is unqualified (subset of first MUS).
	fx := cnfFixture(t)
	scheme := newKWScheme(t, field, fx.ac)
	secret := kw.NewSecret(field.FromUint64(1))
	shares := dealAndCollect(t, scheme, secret)

	// {1,2} has 2 members but is unqualified under this CNF structure.
	quorum := newUnanimity(t, 1, 2)

	_, err := scheme.ConvertShareToAdditive(shares[1], quorum)
	require.Error(t, err)
}
