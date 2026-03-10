package tassa_test

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/hierarchical"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/tassa"
)

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

type benchConfig struct {
	name   string
	levels []*hierarchical.ThresholdLevel
}

var benchConfigs = []benchConfig{
	{
		name: "2-level(2,3)_5p",
		levels: []*hierarchical.ThresholdLevel{
			hierarchical.WithLevel(2, 1, 2, 3),
			hierarchical.WithLevel(3, 4, 5),
		},
	},
	{
		name: "2-level(2,4)_8p",
		levels: []*hierarchical.ThresholdLevel{
			hierarchical.WithLevel(2, 1, 2, 3, 4),
			hierarchical.WithLevel(4, 5, 6, 7, 8),
		},
	},
	{
		name: "3-level(1,2,4)_6p",
		levels: []*hierarchical.ThresholdLevel{
			hierarchical.WithLevel(1, 1, 2),
			hierarchical.WithLevel(2, 3, 4),
			hierarchical.WithLevel(4, 5, 6),
		},
	},
	{
		name: "2-level(3,6)_10p",
		levels: []*hierarchical.ThresholdLevel{
			hierarchical.WithLevel(3, 1, 2, 3, 4, 5),
			hierarchical.WithLevel(6, 6, 7, 8, 9, 10),
		},
	},
}

func newBenchScheme(b *testing.B, cfg benchConfig) (*tassa.Scheme[*k256.Scalar], *hierarchical.HierarchicalConjunctiveThreshold) {
	b.Helper()
	ac, err := hierarchical.NewHierarchicalConjunctiveThresholdAccessStructure(cfg.levels...)
	require.NoError(b, err)
	field := k256.NewScalarField()
	scheme, err := tassa.NewScheme(ac, field)
	require.NoError(b, err)
	return scheme, ac
}

func BenchmarkDeal(b *testing.B) {
	field := k256.NewScalarField()

	for _, cfg := range benchConfigs {
		b.Run(cfg.name, func(b *testing.B) {
			scheme, _ := newBenchScheme(b, cfg)
			secret := tassa.NewSecret(field.FromUint64(42))

			b.ResetTimer()
			for range b.N {
				_, err := scheme.Deal(secret, pcg.NewRandomised())
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDealRandom(b *testing.B) {
	for _, cfg := range benchConfigs {
		b.Run(cfg.name, func(b *testing.B) {
			scheme, _ := newBenchScheme(b, cfg)

			b.ResetTimer()
			for range b.N {
				_, _, err := scheme.DealRandom(pcg.NewRandomised())
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkReconstruct(b *testing.B) {
	field := k256.NewScalarField()

	for _, cfg := range benchConfigs {
		b.Run(cfg.name, func(b *testing.B) {
			scheme, ac := newBenchScheme(b, cfg)
			secret := tassa.NewSecret(field.FromUint64(42))
			out, err := scheme.Deal(secret, pcg.NewRandomised())
			require.NoError(b, err)

			// Build a minimal qualified set: pick from each level to meet thresholds.
			qualifiedShares := minimalQualifiedShares(b, ac, out)

			b.ResetTimer()
			for range b.N {
				_, err := scheme.Reconstruct(qualifiedShares...)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkConvertShareToAdditive(b *testing.B) {
	field := k256.NewScalarField()

	for _, cfg := range benchConfigs {
		b.Run(cfg.name, func(b *testing.B) {
			scheme, ac := newBenchScheme(b, cfg)
			secret := tassa.NewSecret(field.FromUint64(42))
			out, err := scheme.Deal(secret, pcg.NewRandomised())
			require.NoError(b, err)

			qualifiedShares := minimalQualifiedShares(b, ac, out)
			qualifiedIDs := make([]sharing.ID, len(qualifiedShares))
			for i, s := range qualifiedShares {
				qualifiedIDs[i] = s.ID()
			}
			quorum, err := unanimity.NewUnanimityAccessStructure(
				hashset.NewComparable(qualifiedIDs...).Freeze(),
			)
			require.NoError(b, err)

			share := qualifiedShares[0]

			b.ResetTimer()
			for range b.N {
				_, err := scheme.ConvertShareToAdditive(share, quorum)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// minimalQualifiedShares picks a minimal set of shares that satisfies
// every cumulative threshold.
func minimalQualifiedShares(b *testing.B, ac *hierarchical.HierarchicalConjunctiveThreshold, out *tassa.DealerOutput[*k256.Scalar]) []*tassa.Share[*k256.Scalar] {
	b.Helper()

	var ids []sharing.ID
	prevThreshold := 0
	for _, level := range ac.Levels() {
		need := level.Threshold() - prevThreshold
		members := level.Shareholders().List()
		slices.Sort(members)
		ids = append(ids, members[:need]...)
		prevThreshold = level.Threshold()
	}

	shares := make([]*tassa.Share[*k256.Scalar], 0, len(ids))
	for _, id := range ids {
		s, ok := out.Shares().Get(id)
		require.True(b, ok)
		shares = append(shares, s)
	}
	return shares
}
