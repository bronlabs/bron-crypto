package kw_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
)

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

type benchConfig struct {
	name      string
	threshold uint
	total     uint
}

var benchConfigs = []benchConfig{
	{"2-of-3", 2, 3},
	{"3-of-5", 3, 5},
	{"5-of-10", 5, 10},
	{"10-of-20", 10, 20},
}

func BenchmarkDeal(b *testing.B) {
	field := k256.NewScalarField()

	for _, config := range benchConfigs {
		b.Run(config.name, func(b *testing.B) {
			ac, err := threshold.NewThresholdAccessStructure(config.threshold, sharing.NewOrdinalShareholderSet(config.total))
			require.NoError(b, err)
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

func BenchmarkReconstruct(b *testing.B) {
	field := k256.NewScalarField()

	for _, config := range benchConfigs {
		b.Run(config.name, func(b *testing.B) {
			ac, err := threshold.NewThresholdAccessStructure(config.threshold, sharing.NewOrdinalShareholderSet(config.total))
			require.NoError(b, err)
			scheme := newKWScheme(b, field, ac)

			secret := kw.NewSecret(field.FromUint64(42))
			shares := dealAndCollect(b, scheme, secret)

			// Pick exactly threshold shares.
			qualifiedIDs := make([]sharing.ID, 0, config.threshold)
			for id := range shares {
				qualifiedIDs = append(qualifiedIDs, id)
				if uint(len(qualifiedIDs)) == config.threshold {
					break
				}
			}
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

	for _, config := range benchConfigs {
		b.Run(config.name, func(b *testing.B) {
			ac, err := threshold.NewThresholdAccessStructure(config.threshold, sharing.NewOrdinalShareholderSet(config.total))
			require.NoError(b, err)
			scheme := newKWScheme(b, field, ac)

			secret := kw.NewSecret(field.FromUint64(42))
			shares := dealAndCollect(b, scheme, secret)

			quorum, err := unanimity.NewUnanimityAccessStructure(ac.Shareholders())
			require.NoError(b, err)

			share := shares[sharing.ID(1)]

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
