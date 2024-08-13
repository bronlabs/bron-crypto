package internal_test

import (
	"math/big"
	"os"
	"testing"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/internal"
)

func Test_MeasureConstantTime_bigint(t *testing.T) {
	t.Parallel()
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	mod := new(big.Int).SetBytes(internal.GetBigEndianBytesWithLowestBitsSet(256, 256))
	b := new(big.Int)
	exp := new(big.Int)
	internal.RunMeasurement(500, "bigint", func(i int) {
		exp = new(big.Int).SetBytes(internal.GetBigEndianBytesWithLowestBitsSet(64, i))
		b.SetBytes(internal.GetBigEndianBytesWithLowestBitsSet(512, 512))
	}, func() {
		b.Exp(b, exp, mod)
	})
}

func Test_MeasureConstantTime_saferith(t *testing.T) {
	t.Parallel()
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	mod := saferith.ModulusFromBytes(internal.GetBigEndianBytesWithLowestBitsSet(256, 256))
	b := saferith.Nat{}
	exp := saferith.Nat{}
	internal.RunMeasurement(500, "saferith", func(i int) {
		b.SetBytes(internal.GetBigEndianBytesWithLowestBitsSet(512, 512))
		exp.SetBytes(internal.GetBigEndianBytesWithLowestBitsSet(64, i))
	}, func() {
		b.Exp(&b, &exp, mod)
	})
}
