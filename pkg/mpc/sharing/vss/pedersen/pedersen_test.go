package pedersen_test

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
	pedcom "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/boolexpr"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/cnf"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/hierarchical"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/pedersen"
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

func newPedersenKey[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](
	tb testing.TB,
	curve algebra.PrimeGroup[E, S],
) *pedcom.Key[E, S] {
	tb.Helper()
	g := curve.Generator()
	h, err := curve.Hash([]byte("meta-pedersen-test-h"))
	require.NoError(tb, err)
	key, err := pedcom.NewCommitmentKey(g, h)
	require.NoError(tb, err)
	return key
}

func newPedersenScheme[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](
	tb testing.TB,
	key *pedcom.Key[E, S],
	ac accessstructures.Monotone,
) *pedersen.Scheme[E, S] {
	tb.Helper()
	scheme, err := pedersen.NewScheme(key, ac)
	require.NoError(tb, err)
	return scheme
}

func dealPedersen[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](
	tb testing.TB,
	scheme *pedersen.Scheme[E, S],
	secret *kw.Secret[S],
) (*pedersen.DealerOutput[E, S], map[sharing.ID]*pedersen.Share[S]) {
	tb.Helper()
	out, err := scheme.Deal(secret, pcg.NewRandomised())
	require.NoError(tb, err)
	m := make(map[sharing.ID]*pedersen.Share[S])
	for id, sh := range out.Shares().Iter() {
		m[id] = sh
	}
	return out, m
}

func pickShares[S algebra.PrimeFieldElement[S]](m map[sharing.ID]*pedersen.Share[S], ids ...sharing.ID) []*pedersen.Share[S] {
	out := make([]*pedersen.Share[S], len(ids))
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

func boolexprAndOrFixture(t *testing.T) acFixture {
	t.Helper()
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
		boolexprAndOrFixture(t),
	}
}

// ---------------------------------------------------------------------------
// NewScheme – construction
// ---------------------------------------------------------------------------

func TestNewScheme(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	key := newPedersenKey(t, curve)

	t.Run("valid with each access structure", func(t *testing.T) {
		t.Parallel()
		for _, fx := range allFixtures(t) {
			t.Run(fx.name, func(t *testing.T) {
				t.Parallel()
				scheme, err := pedersen.NewScheme(key, fx.ac)
				require.NoError(t, err)
				require.NotNil(t, scheme)
				require.Equal(t, pedersen.Name, scheme.Name())
				require.Equal(t, len(fx.shareholders), scheme.Shareholders().Size())
			})
		}
	})

	t.Run("nil key", func(t *testing.T) {
		t.Parallel()
		ac, err := threshold.NewThresholdAccessStructure(2, shareholders(1, 2, 3))
		require.NoError(t, err)
		_, err = pedersen.NewScheme[*k256.Point, *k256.Scalar](nil, ac)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrIsNil)
	})

	t.Run("nil access structure", func(t *testing.T) {
		t.Parallel()
		_, err := pedersen.NewScheme[*k256.Point, *k256.Scalar](key, nil)
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
	key := newPedersenKey(t, curve)

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newPedersenScheme(t, key, fx.ac)
			secret := kw.NewSecret(field.FromUint64(42))
			_, shares := dealPedersen(t, scheme, secret)

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
	key := newPedersenKey(t, curve)

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newPedersenScheme(t, key, fx.ac)
			secret := kw.NewSecret(field.FromUint64(654321))
			_, shares := dealPedersen(t, scheme, secret)

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
// Verification: every honest share passes Verify
// ---------------------------------------------------------------------------

func TestVerify_HonestShares(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	key := newPedersenKey(t, curve)

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newPedersenScheme(t, key, fx.ac)
			secret := kw.NewSecret(field.FromUint64(9999))
			out, _ := dealPedersen(t, scheme, secret)
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
// Verification: tampered secret component is detected
// ---------------------------------------------------------------------------

func TestVerify_TamperedSecret(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	key := newPedersenKey(t, curve)

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newPedersenScheme(t, key, fx.ac)
			secret := kw.NewSecret(field.FromUint64(1234))
			out, _ := dealPedersen(t, scheme, secret)
			ref := out.VerificationMaterial()

			id := fx.shareholders[0]
			honest, ok := out.Shares().Get(id)
			require.True(t, ok)

			// Tamper with the secret component only, keep blinding intact
			tamperedSecretVals := make([]FE, len(honest.Value()))
			for i, v := range honest.Value() {
				tamperedSecretVals[i] = v.Add(field.One())
			}
			tamperedSecret, err := kw.NewShare(id, tamperedSecretVals...)
			require.NoError(t, err)

			blindingVals := make([]FE, len(honest.Blinding()))
			for i, w := range honest.Blinding() {
				blindingVals[i] = w.Value()
			}
			blindingShare, err := kw.NewShare(id, blindingVals...)
			require.NoError(t, err)

			tampered, err := pedersen.NewShare(id, tamperedSecret, blindingShare)
			require.NoError(t, err)

			err = scheme.Verify(tampered, ref)
			require.Error(t, err)
			require.ErrorIs(t, err, sharing.ErrVerification)
		})
	}
}

// ---------------------------------------------------------------------------
// Verification: tampered blinding component is detected
// ---------------------------------------------------------------------------

func TestVerify_TamperedBlinding(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	key := newPedersenKey(t, curve)

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newPedersenScheme(t, key, fx.ac)
			secret := kw.NewSecret(field.FromUint64(5678))
			out, _ := dealPedersen(t, scheme, secret)
			ref := out.VerificationMaterial()

			id := fx.shareholders[0]
			honest, ok := out.Shares().Get(id)
			require.True(t, ok)

			// Keep secret intact, tamper with blinding
			secretVals := honest.Value()
			secretShare, err := kw.NewShare(id, secretVals...)
			require.NoError(t, err)

			tamperedBlindingVals := make([]FE, len(honest.Blinding()))
			for i, w := range honest.Blinding() {
				tamperedBlindingVals[i] = w.Value().Add(field.One())
			}
			tamperedBlinding, err := kw.NewShare(id, tamperedBlindingVals...)
			require.NoError(t, err)

			tampered, err := pedersen.NewShare(id, secretShare, tamperedBlinding)
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
	key := newPedersenKey(t, curve)

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newPedersenScheme(t, key, fx.ac)
			s1 := kw.NewSecret(field.FromUint64(100))
			s2 := kw.NewSecret(field.FromUint64(200))

			out1, _ := dealPedersen(t, scheme, s1)
			out2, _ := dealPedersen(t, scheme, s2)

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
	key := newPedersenKey(t, curve)

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newPedersenScheme(t, key, fx.ac)
			secret := kw.NewSecret(field.FromUint64(77777))
			out, shares := dealPedersen(t, scheme, secret)
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
	key := newPedersenKey(t, curve)
	fx := thresholdFixture(t)
	scheme := newPedersenScheme(t, key, fx.ac)
	secret := kw.NewSecret(field.FromUint64(42))
	out, shares := dealPedersen(t, scheme, secret)
	ref := out.VerificationMaterial()

	qset := fx.qualified[0]
	picked := pickShares(shares, qset...)
	honest := picked[0]

	// Tamper with secret component
	tamperedSecretVals := make([]FE, len(honest.Value()))
	for i, v := range honest.Value() {
		tamperedSecretVals[i] = v.Add(field.One())
	}
	tamperedSecret, err := kw.NewShare(honest.ID(), tamperedSecretVals...)
	require.NoError(t, err)

	blindingVals := make([]FE, len(honest.Blinding()))
	for i, w := range honest.Blinding() {
		blindingVals[i] = w.Value()
	}
	blindingShare, err := kw.NewShare(honest.ID(), blindingVals...)
	require.NoError(t, err)

	tampered, err := pedersen.NewShare(honest.ID(), tamperedSecret, blindingShare)
	require.NoError(t, err)
	picked[0] = tampered

	_, err = scheme.ReconstructAndVerify(ref, picked...)
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
	key := newPedersenKey(t, curve)
	fx := thresholdFixture(t)
	scheme := newPedersenScheme(t, key, fx.ac)

	out, _ := dealPedersen(t, scheme, kw.NewSecret(field.One()))
	err := scheme.Verify(nil, out.VerificationMaterial())
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrIsNil)
}

// ---------------------------------------------------------------------------
// Verify nil verification vector
// ---------------------------------------------------------------------------

func TestVerify_NilVerificationVector(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	key := newPedersenKey(t, curve)
	fx := thresholdFixture(t)
	scheme := newPedersenScheme(t, key, fx.ac)

	out, _ := dealPedersen(t, scheme, kw.NewSecret(field.One()))
	sh, ok := out.Shares().Get(fx.shareholders[0])
	require.True(t, ok)
	err := scheme.Verify(sh, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrIsNil)
}

// ---------------------------------------------------------------------------
// DealRandom: returns valid output and reconstructs
// ---------------------------------------------------------------------------

func TestDealRandom(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	key := newPedersenKey(t, curve)

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newPedersenScheme(t, key, fx.ac)

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
			m := make(map[sharing.ID]*pedersen.Share[*k256.Scalar])
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
	key := newPedersenKey(t, curve)
	fx := thresholdFixture(t)
	scheme := newPedersenScheme(t, key, fx.ac)
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
	key := newPedersenKey(t, curve)

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newPedersenScheme(t, key, fx.ac)
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
// DealerFunc produces shares consistent with dealing output
// ---------------------------------------------------------------------------

func TestDealerFunc_SharesConsistent(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	key := newPedersenKey(t, curve)

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newPedersenScheme(t, key, fx.ac)
			secret := kw.NewSecret(field.FromUint64(31337))

			out, df, err := scheme.DealAndRevealDealerFunc(secret, pcg.NewRandomised())
			require.NoError(t, err)

			for _, id := range fx.shareholders {
				outShare, ok := out.Shares().Get(id)
				require.True(t, ok)

				dfShare, err := df.ShareOf(id)
				require.NoError(t, err)

				require.True(t, outShare.Equal(dfShare),
					"dealer output share and dealer func share must match for ID %d", id)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Pedersen core equation: Com(λ_i) == M_i · V
// For each shareholder, the Pedersen commitment of the share components
// must equal the left module action of the shareholder's MSP rows on V.
// ---------------------------------------------------------------------------

func TestPedersenCoreEquation(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	key := newPedersenKey(t, curve)

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newPedersenScheme(t, key, fx.ac)
			secret := kw.NewSecret(field.FromUint64(31337))

			out, df, err := scheme.DealAndRevealDealerFunc(secret, pcg.NewRandomised())
			require.NoError(t, err)
			vv := out.VerificationMaterial()

			for _, id := range fx.shareholders {
				sh, ok := out.Shares().Get(id)
				require.True(t, ok)

				// Manually lift the share via Pedersen commitments
				manuallyLifted, err := pedersen.LiftShare[*k256.Point](sh, key)
				require.NoError(t, err)

				// Compute lifted share from verification vector via M_i · V
				ldf, err := pedersen.NewLiftedDealerFunc(vv, df.G().MSP())
				require.NoError(t, err)
				expectedLifted, err := ldf.ShareOf(id)
				require.NoError(t, err)

				require.True(t, expectedLifted.Equal(manuallyLifted),
					"Pedersen equation failed for ID %d: M_i · V ≠ Com(λ_i)", id)
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
	key := newPedersenKey(t, curve)
	prng := pcg.NewRandomised()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newPedersenScheme(t, key, fx.ac)

			for range 5 {
				val, err := field.Random(prng)
				require.NoError(t, err)
				secret := kw.NewSecret(val)
				out, shares := dealPedersen(t, scheme, secret)
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
	key := newPedersenKey(t, curve)

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newPedersenScheme(t, key, fx.ac)
			secret := kw.NewSecret(field.Zero())
			out, shares := dealPedersen(t, scheme, secret)
			ref := out.VerificationMaterial()

			for _, sh := range out.Shares().Values() {
				require.NoError(t, scheme.Verify(sh, ref))
			}

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
	key := newPedersenKey(t, curve)

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newPedersenScheme(t, key, fx.ac)

			s1 := kw.NewSecret(field.FromUint64(500))
			s2 := kw.NewSecret(field.FromUint64(300))

			_, shares1 := dealPedersen(t, scheme, s1)
			_, shares2 := dealPedersen(t, scheme, s2)

			combined := make(map[sharing.ID]*pedersen.Share[*k256.Scalar], len(shares1))
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
// Homomorphic addition preserves verification:
// V1 + V2 verifies combined shares
// ---------------------------------------------------------------------------

func TestHomomorphicAddition_VerificationVectorSum(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	key := newPedersenKey(t, curve)

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newPedersenScheme(t, key, fx.ac)

			s1 := kw.NewSecret(field.FromUint64(111))
			s2 := kw.NewSecret(field.FromUint64(222))

			out1, shares1 := dealPedersen(t, scheme, s1)
			out2, shares2 := dealPedersen(t, scheme, s2)

			// V_combined = V1 + V2
			combinedVV := out1.VerificationMaterial().Op(out2.VerificationMaterial())

			// Combined shares
			combined := make(map[sharing.ID]*pedersen.Share[*k256.Scalar], len(shares1))
			for id, sh1 := range shares1 {
				combined[id] = sh1.Add(shares2[id])
			}

			// Each combined share must verify against V_combined
			for _, id := range fx.shareholders {
				err := scheme.Verify(combined[id], combinedVV)
				require.NoError(t, err,
					"combined share must verify against sum of verification vectors for ID %d", id)
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
	key := newPedersenKey(t, curve)

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newPedersenScheme(t, key, fx.ac)

			s := kw.NewSecret(field.FromUint64(42))
			scalar := field.FromUint64(7)

			_, shares := dealPedersen(t, scheme, s)

			scaled := make(map[sharing.ID]*pedersen.Share[*k256.Scalar], len(shares))
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
// ---------------------------------------------------------------------------

func TestPrivacy_SingleShareRevealsNothing(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	key := newPedersenKey(t, curve)

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newPedersenScheme(t, key, fx.ac)

			s1 := kw.NewSecret(field.FromUint64(100))
			s2 := kw.NewSecret(field.FromUint64(200))

			_, shares1 := dealPedersen(t, scheme, s1)
			_, shares2 := dealPedersen(t, scheme, s2)

			for _, id := range fx.shareholders {
				require.False(t, shares1[id].Equal(shares2[id]),
					"shares for ID %d should be randomised independently", id)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Pedersen hiding: same secret with different randomness yields different
// verification vectors (unlike Feldman where V reveals [s]G)
// ---------------------------------------------------------------------------

func TestPedersenHiding_SameSecretDifferentVV(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	key := newPedersenKey(t, curve)
	fx := thresholdFixture(t)
	scheme := newPedersenScheme(t, key, fx.ac)

	secret := kw.NewSecret(field.FromUint64(42))
	out1, _ := dealPedersen(t, scheme, secret)
	out2, _ := dealPedersen(t, scheme, secret)

	require.False(t, out1.VerificationMaterial().Equal(out2.VerificationMaterial()),
		"same secret dealt twice must produce different verification vectors (hiding)")
}

// ---------------------------------------------------------------------------
// Determinism: same PRNG seed → identical outputs
// ---------------------------------------------------------------------------

func TestDeterminism(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	key := newPedersenKey(t, curve)
	fx := thresholdFixture(t)
	scheme := newPedersenScheme(t, key, fx.ac)
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
	key := newPedersenKey(t, curve)
	fx := thresholdFixture(t)
	scheme := newPedersenScheme(t, key, fx.ac)

	out1, _ := dealPedersen(t, scheme, kw.NewSecret(field.FromUint64(1)))
	out2, _ := dealPedersen(t, scheme, kw.NewSecret(field.FromUint64(1)))

	require.False(t, out1.VerificationMaterial().Equal(out2.VerificationMaterial()),
		"distinct dealings should produce distinct verification vectors")
}

// ---------------------------------------------------------------------------
// ConvertShareToAdditive: sum of additive shares recovers the secret
// ---------------------------------------------------------------------------

func TestConvertShareToAdditive(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	key := newPedersenKey(t, curve)

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newPedersenScheme(t, key, fx.ac)
			secret := kw.NewSecret(field.FromUint64(42))
			_, shares := dealPedersen(t, scheme, secret)

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
	key := newPedersenKey(t, curve)

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newPedersenScheme(t, key, fx.ac)
			secret := kw.NewSecret(field.FromUint64(77))
			_, shares := dealPedersen(t, scheme, secret)

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
// Share CBOR round-trip
// ---------------------------------------------------------------------------

func TestShare_CBOR(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	key := newPedersenKey(t, curve)
	fx := thresholdFixture(t)
	scheme := newPedersenScheme(t, key, fx.ac)
	secret := kw.NewSecret(field.FromUint64(777))
	out, _ := dealPedersen(t, scheme, secret)

	for _, id := range fx.shareholders {
		t.Run(fmt.Sprintf("id=%d", id), func(t *testing.T) {
			t.Parallel()
			sh, ok := out.Shares().Get(id)
			require.True(t, ok)

			data, err := sh.MarshalCBOR()
			require.NoError(t, err)

			var decoded pedersen.Share[*k256.Scalar]
			err = decoded.UnmarshalCBOR(data)
			require.NoError(t, err)
			require.True(t, sh.Equal(&decoded))
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
	key := newPedersenKey(t, curve)
	fx := thresholdFixture(t)
	scheme := newPedersenScheme(t, key, fx.ac)
	secret := kw.NewSecret(field.FromUint64(777))
	out, _ := dealPedersen(t, scheme, secret)

	for _, id := range fx.shareholders {
		t.Run(fmt.Sprintf("id=%d", id), func(t *testing.T) {
			t.Parallel()
			sh, ok := out.Shares().Get(id)
			require.True(t, ok)

			lifted, err := pedersen.LiftShare[*k256.Point](sh, key)
			require.NoError(t, err)

			data, err := lifted.MarshalCBOR()
			require.NoError(t, err)

			var decoded pedersen.LiftedShare[*k256.Point, *k256.Scalar]
			err = decoded.UnmarshalCBOR(data)
			require.NoError(t, err)
			require.True(t, lifted.Equal(&decoded))
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
	key := newPedersenKey(t, g1)

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme, err := pedersen.NewScheme(key, fx.ac)
			require.NoError(t, err)

			secret := kw.NewSecret(field.FromUint64(999999))
			out, err := scheme.Deal(secret, pcg.NewRandomised())
			require.NoError(t, err)
			ref := out.VerificationMaterial()

			m := make(map[sharing.ID]*pedersen.Share[*bls12381.Scalar])
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
	key := newPedersenKey(t, g2)

	fx := thresholdFixture(t)
	scheme, err := pedersen.NewScheme(key, fx.ac)
	require.NoError(t, err)

	secret := kw.NewSecret(field.FromUint64(54321))
	out, err := scheme.Deal(secret, pcg.NewRandomised())
	require.NoError(t, err)
	ref := out.VerificationMaterial()

	m := make(map[sharing.ID]*pedersen.Share[*bls12381.Scalar])
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
// with extra group elements, hoping to inject additional degrees of freedom.
// The left module action M * V enforces dim(V) == MSP.D(), so the extended
// vector must be rejected.
// ---------------------------------------------------------------------------

func TestDahlgrenAttack_ExtendedVerificationVector(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	key := newPedersenKey(t, curve)

	fx := largeThresholdFixture(t) // threshold(4,7) → D=4
	scheme := newPedersenScheme(t, key, fx.ac)
	secret := kw.NewSecret(field.FromUint64(42))
	prng := pcg.NewRandomised()

	out, df, err := scheme.DealAndRevealDealerFunc(secret, prng)
	require.NoError(t, err)

	// Reconstruct the random columns from the dealer func
	gRC := df.G().RandomColumn()
	hRC := df.H().RandomColumn()
	d, _ := gRC.Dimensions()

	// Build extended columns: honest D entries + one extra random entry
	extraG, err := field.Random(prng)
	require.NoError(t, err)
	extraH, err := field.Random(prng)
	require.NoError(t, err)

	extMod, err := mat.NewMatrixModule(uint(d+1), 1, field)
	require.NoError(t, err)

	gEntries := make([]*k256.Scalar, d+1)
	hEntries := make([]*k256.Scalar, d+1)
	for i := range d {
		gEntries[i], err = gRC.Get(i, 0)
		require.NoError(t, err)
		hEntries[i], err = hRC.Get(i, 0)
		require.NoError(t, err)
	}
	gEntries[d] = extraG
	hEntries[d] = extraH

	extGCol, err := extMod.NewRowMajor(gEntries...)
	require.NoError(t, err)
	extHCol, err := extMod.NewRowMajor(hEntries...)
	require.NoError(t, err)

	// Lift with respective generators: V_ext = [r_g_ext]G + [r_h_ext]H
	liftedG, err := mat.Lift(extGCol, key.G())
	require.NoError(t, err)
	liftedH, err := mat.Lift(extHCol, key.H())
	require.NoError(t, err)
	extendedVV := liftedG.Op(liftedH)

	vv, err := feldman.NewVerificationVector(extendedVV, nil)
	require.NoError(t, err)

	// Verify must fail: extended V has dimension D+1 but M has D columns
	sh, ok := out.Shares().Get(fx.shareholders[0])
	require.True(t, ok)
	err = scheme.Verify(sh, vv)
	require.Error(t, err, "extended verification vector must be rejected (Dahlgren attack)")
}

// ---------------------------------------------------------------------------
// Arbitrary (non-sequential) shareholder IDs
// ---------------------------------------------------------------------------

func TestArbitraryIDs(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	key := newPedersenKey(t, curve)
	ac, err := threshold.NewThresholdAccessStructure(2, shareholders(10, 100, 1000))
	require.NoError(t, err)
	scheme := newPedersenScheme(t, key, ac)

	secret := kw.NewSecret(field.FromUint64(54321))
	out, shares := dealPedersen(t, scheme, secret)
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
// Multi-row shareholders (non-ideal MSP): verification still works
// CNF access structures produce non-ideal MSPs where shareholders own
// multiple MSP rows.
// ---------------------------------------------------------------------------

func TestVerify_MultiRowShareholders(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	key := newPedersenKey(t, curve)

	fx := cnfThreeClauseFixture(t) // non-ideal MSP
	scheme := newPedersenScheme(t, key, fx.ac)
	secret := kw.NewSecret(field.FromUint64(31337))
	out, shares := dealPedersen(t, scheme, secret)
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
// Blinding independence: reconstruction only depends on the secret component,
// not on blinding. Two dealings with the same secret (different randomness)
// yield different shares but the same reconstructed value.
// ---------------------------------------------------------------------------

func TestBlindingIndependence(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	key := newPedersenKey(t, curve)

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newPedersenScheme(t, key, fx.ac)
			secret := kw.NewSecret(field.FromUint64(42))

			_, shares1 := dealPedersen(t, scheme, secret)
			_, shares2 := dealPedersen(t, scheme, secret)

			for _, qset := range fx.qualified {
				r1, err := scheme.Reconstruct(pickShares(shares1, qset...)...)
				require.NoError(t, err)
				r2, err := scheme.Reconstruct(pickShares(shares2, qset...)...)
				require.NoError(t, err)
				require.True(t, r1.Equal(r2),
					"reconstruction must yield same secret regardless of blinding")
			}

			// But the shares themselves must differ (different blinding)
			for _, id := range fx.shareholders {
				require.False(t, shares1[id].Equal(shares2[id]),
					"shares with different blinding should not be equal for ID %d", id)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Deal error cases
// ---------------------------------------------------------------------------

func TestDeal_NilSecret(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	key := newPedersenKey(t, curve)
	fx := thresholdFixture(t)
	scheme := newPedersenScheme(t, key, fx.ac)

	_, err := scheme.Deal(nil, pcg.NewRandomised())
	require.Error(t, err)
}

func TestDeal_NilPRNG(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	key := newPedersenKey(t, curve)
	fx := thresholdFixture(t)
	scheme := newPedersenScheme(t, key, fx.ac)

	_, err := scheme.Deal(kw.NewSecret(field.One()), nil)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// type alias to shorten generic constraints
// ---------------------------------------------------------------------------

type FE = *k256.Scalar
