package kw_test

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/hierarchical"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
)

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

type benchConfig struct {
	name string
	ac   func(b *testing.B) accessstructures.Monotone
}

func thresholdAC(t uint, n uint) func(b *testing.B) accessstructures.Monotone {
	return func(b *testing.B) accessstructures.Monotone {
		b.Helper()
		ac, err := threshold.NewThresholdAccessStructure(t, sharing.NewOrdinalShareholderSet(n))
		require.NoError(b, err)
		return ac
	}
}

func hierarchicalAC(levels ...*hierarchical.ThresholdLevel) func(b *testing.B) accessstructures.Monotone {
	return func(b *testing.B) accessstructures.Monotone {
		b.Helper()
		ac, err := hierarchical.NewHierarchicalConjunctiveThresholdAccessStructure(levels...)
		require.NoError(b, err)
		return ac
	}
}

var benchConfigs = []benchConfig{
	{"threshold/2-of-3", thresholdAC(2, 3)},
	{"threshold/3-of-5", thresholdAC(3, 5)},
	{"threshold/5-of-10", thresholdAC(5, 10)},
	{"threshold/10-of-20", thresholdAC(10, 20)},
	{
		"hierarchical/2-level(2,4)_8p",
		hierarchicalAC(
			hierarchical.WithLevel(2, 1, 2, 3, 4),
			hierarchical.WithLevel(4, 5, 6, 7, 8),
		),
	},
	{
		"hierarchical/3-level(1,2,4)_6p",
		hierarchicalAC(
			hierarchical.WithLevel(1, 1, 2),
			hierarchical.WithLevel(2, 3, 4),
			hierarchical.WithLevel(4, 5, 6),
		),
	},
}

func BenchmarkDeal(b *testing.B) {
	field := k256.NewScalarField()

	for _, cfg := range benchConfigs {
		b.Run(cfg.name, func(b *testing.B) {
			ac := cfg.ac(b)
			scheme := newKWScheme(b, field, ac)
			secret := kw.NewSecret(field.FromUint64(42))

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
	field := k256.NewScalarField()

	for _, cfg := range benchConfigs {
		b.Run(cfg.name, func(b *testing.B) {
			ac := cfg.ac(b)
			scheme := newKWScheme(b, field, ac)

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
			ac := cfg.ac(b)
			scheme := newKWScheme(b, field, ac)

			secret := kw.NewSecret(field.FromUint64(42))
			shares := dealAndCollect(b, scheme, secret)

			qualifiedIDs := minimalQualifiedIDs(ac)
			qualifiedShares := pickShares(shares, qualifiedIDs...)

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
			ac := cfg.ac(b)
			scheme := newKWScheme(b, field, ac)

			secret := kw.NewSecret(field.FromUint64(42))
			shares := dealAndCollect(b, scheme, secret)

			qualifiedIDs := minimalQualifiedIDs(ac)
			quorum, err := unanimity.NewUnanimityAccessStructure(shareholders(qualifiedIDs...))
			require.NoError(b, err)

			share := shares[qualifiedIDs[0]]

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

// minimalQualifiedIDs returns a minimal set of shareholder IDs that satisfies
// the access structure. For threshold it picks the first t IDs; for hierarchical
// it picks enough from each level.
func minimalQualifiedIDs(ac accessstructures.Monotone) []sharing.ID {
	switch a := ac.(type) {
	case *threshold.Threshold:
		ids := a.Shareholders().List()
		slices.Sort(ids)
		return ids[:a.Threshold()]
	case *hierarchical.HierarchicalConjunctiveThreshold:
		var ids []sharing.ID
		prevThreshold := 0
		for _, level := range a.Levels() {
			need := level.Threshold() - prevThreshold
			members := level.Shareholders().List()
			slices.Sort(members)
			ids = append(ids, members[:need]...)
			prevThreshold = level.Threshold()
		}
		return ids
	default:
		// Fallback: return all shareholders.
		return ac.Shareholders().List()
	}
}

// ---------------------------------------------------------------------------
// formatting helper
// ---------------------------------------------------------------------------

func formatIDs(ids []sharing.ID) string {
	s := "{"
	for i, id := range ids {
		if i > 0 {
			s += ","
		}
		s += string(rune('0' + id%10))
		if id >= 10 {
			// just use Sprintf for multi-digit
			s = ""
			for j, jd := range ids {
				if j > 0 {
					s += ","
				}
				s += func(n sharing.ID) string {
					if n == 0 {
						return "0"
					}
					r := ""
					for n > 0 {
						r = string(rune('0'+n%10)) + r
						n /= 10
					}
					return r
				}(jd)
			}
			return "{" + s + "}"
		}
	}
	return s + "}"
}
