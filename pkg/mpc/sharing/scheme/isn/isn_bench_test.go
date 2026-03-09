package isn_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/isn"
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
	group := k256.NewScalarField()

	for _, config := range benchConfigs {
		b.Run(config.name, func(b *testing.B) {
			ac, err := threshold.NewThresholdAccessStructure(config.threshold, sharing.NewOrdinalShareholderSet(config.total))
			require.NoError(b, err)
			scheme, err := isn.NewFiniteScheme(group, ac)
			require.NoError(b, err)

			secret := isn.NewSecret(group.FromUint64(42))

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
	group := k256.NewScalarField()

	for _, config := range benchConfigs {
		b.Run(config.name, func(b *testing.B) {
			ac, err := threshold.NewThresholdAccessStructure(config.threshold, sharing.NewOrdinalShareholderSet(config.total))
			require.NoError(b, err)
			scheme, err := isn.NewFiniteScheme(group, ac)
			require.NoError(b, err)

			secret := isn.NewSecret(group.FromUint64(42))
			out, err := scheme.Deal(secret, pcg.NewRandomised())
			require.NoError(b, err)

			// Pick exactly threshold shares.
			allShares := out.Shares().Values()
			qualifiedShares := allShares[:config.threshold]

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
	group := k256.NewScalarField()

	for _, config := range benchConfigs {
		b.Run(config.name, func(b *testing.B) {
			ac, err := threshold.NewThresholdAccessStructure(config.threshold, sharing.NewOrdinalShareholderSet(config.total))
			require.NoError(b, err)
			scheme, err := isn.NewFiniteScheme(group, ac)
			require.NoError(b, err)

			secret := isn.NewSecret(group.FromUint64(42))
			out, err := scheme.Deal(secret, pcg.NewRandomised())
			require.NoError(b, err)

			quorum, err := unanimity.NewUnanimityAccessStructure(ac.Shareholders())
			require.NoError(b, err)

			share, exists := out.Shares().Get(sharing.ID(1))
			require.True(b, exists)

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
